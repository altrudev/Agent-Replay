from __future__ import annotations

from collections import defaultdict
from typing import Any

from .model import CanonicalEvent


def mismatches(event: CanonicalEvent) -> list[dict[str, Any]]:
    """Return mismatches only when an observed value is actually present.

    Missing observation is absence of evidence, not evidence of mismatch.
    Explicit JSON null remains an observation and can match or mismatch.
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
    """Return expected fields for which no observed key was supplied."""
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


def _ancestor_index(events: list[CanonicalEvent]) -> dict[str, frozenset[str]]:
    """Build ancestor closures once in topological order.

    normalize.py guarantees that parents precede children, so each closure can
    reuse already-computed parent closures instead of traversing the graph once
    per divergence.
    """
    ancestors: dict[str, frozenset[str]] = {}
    for event in events:
        found: set[str] = set()
        for parent_id in event.parent_ids:
            found.add(parent_id)
            found.update(ancestors.get(parent_id, ()))
        ancestors[event.event_id] = frozenset(found)
    return ancestors


def causal_chain(
    events: list[CanonicalEvent],
    divergences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not divergences:
        return []

    by_id = {event.event_id: event for event in events}
    divergent_ids = {item["event_id"] for item in divergences}
    first_id = divergences[0]["event_id"]
    ancestors = _ancestor_index(events)

    # Prefer explicit provenance links. Where none exist, preserve temporal
    # sequence without claiming an unproved causal edge.
    chain: list[dict[str, Any]] = []
    for item in divergences:
        event = by_id[item["event_id"]]
        explicit = [pid for pid in event.parent_ids if pid in by_id]
        divergent_ancestors = sorted(
            set(ancestors.get(event.event_id, ())) & divergent_ids
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


def evidence_gaps(
    events: list[CanonicalEvent],
    divergences: list[dict[str, Any]],
    chain: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return limits in the supplied evidence without inventing missing facts."""
    gaps: list[dict[str, Any]] = []

    for event in events:
        if not event.expected:
            gaps.append(
                {
                    "type": "UNASSESSED_EVENT",
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "actor": event.actor,
                    "basis": "event has no caller-supplied expected-state assertion",
                    "effect": "Agent Replay cannot establish validity or divergence for this event",
                }
            )

    divergent_ids = {item["event_id"] for item in divergences}
    for item in chain:
        if (
            item["event_id"] in divergent_ids
            and item["relationship"] == "TEMPORALLY_DOWNSTREAM"
        ):
            gaps.append(
                {
                    "type": "MISSING_CAUSAL_LINK",
                    "event_id": item["event_id"],
                    "kind": item["kind"],
                    "actor": item["actor"],
                    "basis": "divergence is later in time but has no explicit divergent ancestor",
                    "effect": "temporal order must not be presented as proof of causation",
                }
            )

    return gaps
