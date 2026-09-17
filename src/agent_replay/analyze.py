from __future__ import annotations

from collections import defaultdict
from typing import Any

from .model import CanonicalEvent


def mismatches(event: CanonicalEvent) -> list[dict[str, Any]]:
    """Return only comparisons where an observed value is actually present.

    Missing observation is not a mismatch. It is absence of evidence and is
    tracked separately by ``not_observed``.
    """
    out: list[dict[str, Any]] = []
    for field, expected in event.expected.items():
        if field not in event.observed:
            continue
        observed = event.observed[field]
        if observed != expected:
            out.append(
                {
                    "field": field,
                    "expected": expected,
                    "observed": observed,
                }
            )
    return out


def not_observed(event: CanonicalEvent) -> list[str]:
    """Return expected fields for which no observed field was supplied.

    This deliberately distinguishes an absent key from an explicitly supplied
    JSON null value. An explicit null remains an observation and can therefore
    match or mismatch an expected value.
    """
    return [field for field in event.expected if field not in event.observed]


def build_divergences(
    events: list[CanonicalEvent],
) -> list[dict[str, Any]]:
    divergences: list[dict[str, Any]] = []
    for event in events:
        mm = mismatches(event)
        if not mm:
            continue
        divergences.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "kind": event.kind,
                "parent_ids": list(event.parent_ids),
                "source_line": event.source_line,
                "evidence": event.evidence,
                "mismatches": mm,
            }
        )
    return divergences


def _explicit_ancestors(
    event_id: str,
    by_id: dict[str, CanonicalEvent],
) -> set[str]:
    found: set[str] = set()
    stack = list(by_id[event_id].parent_ids)
    while stack:
        current = stack.pop()
        if current in found or current not in by_id:
            continue
        found.add(current)
        stack.extend(by_id[current].parent_ids)
    return found


def causal_chain(
    events: list[CanonicalEvent],
    divergences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not divergences:
        return []

    by_id = {event.event_id: event for event in events}
    divergent_ids = {item["event_id"] for item in divergences}
    first_id = divergences[0]["event_id"]

    # Prefer explicit provenance links. Where none exist, preserve temporal
    # sequence without claiming an unproved causal edge.
    chain: list[dict[str, Any]] = []
    for item in divergences:
        event = by_id[item["event_id"]]
        explicit = [
            pid for pid in event.parent_ids
            if pid in by_id
        ]
        divergent_ancestors = sorted(
            _explicit_ancestors(event.event_id, by_id) & divergent_ids
        )
        chain.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "kind": event.kind,
                "actor": event.actor,
                "relationship": (
                    "ROOT_DIVERGENCE"
                    if event.event_id == first_id
                    else "EXPLICITLY_DOWNSTREAM"
                    if divergent_ancestors
                    else "TEMPORALLY_DOWNSTREAM"
                ),
                "direct_parent_ids": explicit,
                "divergent_ancestor_ids": divergent_ancestors,
            }
        )
    return chain


def attribution(
    divergences: list[dict[str, Any]],
    chain: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not divergences:
        return []

    downstream = {
        item["event_id"]: item["relationship"]
        for item in chain
    }
    first_id = divergences[0]["event_id"]
    actors: dict[str, list[str]] = defaultdict(list)
    for item in divergences:
        actors[item["actor"]].append(item["event_id"])

    out: list[dict[str, Any]] = []
    for actor, event_ids in actors.items():
        if first_id in event_ids:
            role = "PRIMARY"
            basis = "actor owns the earliest provable divergence"
        elif any(
            downstream.get(event_id) == "EXPLICITLY_DOWNSTREAM"
            for event_id in event_ids
        ):
            role = "CONTRIBUTING"
            basis = "actor owns a divergent event explicitly downstream of another divergence"
        else:
            role = "DOWNSTREAM"
            basis = "actor owns later divergent evidence without an explicit causal edge"

        out.append(
            {
                "actor": actor,
                "role": role,
                "event_ids": event_ids,
                "basis": basis,
            }
        )

    order = {"PRIMARY": 0, "CONTRIBUTING": 1, "DOWNSTREAM": 2}
    return sorted(out, key=lambda x: (order[x["role"]], x["actor"]))


def confidence(
    divergences: list[dict[str, Any]],
    chain: list[dict[str, Any]],
) -> str:
    if not divergences:
        return "NONE"
    if len(divergences) == 1:
        return "HIGH"
    if any(item["relationship"] == "EXPLICITLY_DOWNSTREAM" for item in chain[1:]):
        return "HIGH"
    return "MEDIUM"
