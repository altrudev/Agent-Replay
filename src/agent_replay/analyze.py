from __future__ import annotations

from collections import defaultdict
from typing import Any

from .model import CanonicalEvent


def comparisons(event: CanonicalEvent) -> list[dict[str, Any]]:
    out = []
    for field in sorted(event.expected.keys() | event.observed.keys()):
        item = {"field": field}
        if field in event.expected:
            item["expected"] = event.expected[field]
        if field in event.observed:
            item["observed"] = event.observed[field]
        item["status"] = (
            "NOT_COMPARABLE" if field not in event.expected else
            "NOT_OBSERVED" if field not in event.observed else
            "MATCH" if event.observed[field] == event.expected[field] else "MISMATCH"
        )
        out.append(item)
    return out


def mismatches(event: CanonicalEvent) -> list[dict[str, Any]]:
    return [{k: v for k, v in item.items() if k != "status"}
            for item in comparisons(event) if item["status"] == "MISMATCH"]


def first_frontier(events, divergences):
    from .normalize import _event_time_ns
    if not divergences:
        return []
    by_id = {event.event_id: event for event in events}
    earliest = _event_time_ns(by_id[divergences[0]["event_id"]])
    candidates = {d["event_id"] for d in divergences
                  if _event_time_ns(by_id[d["event_id"]]) == earliest}
    downstream = {}
    frontier = []
    for event in events:
        inherited = any(downstream.get(p, False) for p in event.parent_ids)
        if event.event_id in candidates and not inherited:
            frontier.append(event.event_id)
        downstream[event.event_id] = inherited or event.event_id in candidates
    frontier_ids = set(frontier)
    return [d for d in divergences if d["event_id"] in frontier_ids]


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



def causal_chain(
    events: list[CanonicalEvent],
    divergences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not divergences:
        return []

    by_id = {event.event_id: event for event in events}
    divergent_ids = {item["event_id"] for item in divergences}
    frontier_ids = {d["event_id"] for d in first_frontier(events, divergences)}
    limit = 128

    # Prefer explicit provenance links. Where none exist, preserve temporal
    # sequence without claiming an unproved causal edge.
    chain: list[dict[str, Any]] = []
    for item in divergences:
        event = by_id[item["event_id"]]
        explicit = [pid for pid in event.parent_ids if pid in by_id]
        # Traverse per divergence: linear working memory, no transitive closures.
        seen = set()
        pending = list(event.parent_ids)
        found = set()
        while pending:
            parent = pending.pop()
            if parent in seen:
                continue
            seen.add(parent)
            if parent in divergent_ids:
                found.add(parent)
            pending.extend(by_id[parent].parent_ids)
        ancestor_count = len(found)
        divergent_ancestors = sorted(found)[:limit]
        chain.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "kind": event.kind,
                "actor": event.actor,
                "relationship": (
                    "ROOT_DIVERGENCE"
                    if event.event_id in frontier_ids
                    else "EXPLICITLY_DOWNSTREAM"
                    if divergent_ancestors
                    else "TEMPORALLY_DOWNSTREAM"
                ),
                "direct_parent_ids": explicit,
                "divergent_ancestor_ids": divergent_ancestors,
                "divergent_ancestor_count": ancestor_count,
                "ancestors_truncated": ancestor_count > limit,
                "ancestor_output_limit": limit,
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
    first_ids = {item["event_id"] for item in chain if item["relationship"] == "ROOT_DIVERGENCE"}
    actors: dict[str, list[str]] = defaultdict(list)
    for item in divergences:
        actors[item["actor"]].append(item["event_id"])

    out: list[dict[str, Any]] = []
    for actor, event_ids in actors.items():
        if first_ids.intersection(event_ids):
            role = "PRIMARY"
            basis = "source actor label associated with the earliest divergence frontier"
        elif any(
            downstream.get(event_id) == "EXPLICITLY_DOWNSTREAM"
            for event_id in event_ids
        ):
            role = "CONTRIBUTING"
            basis = "source actor label associated with a divergent event explicitly downstream of another divergence"
        else:
            role = "DOWNSTREAM"
            basis = "source actor label associated with later divergent evidence without an explicit causal edge"

        out.append(
            {
                "actor": actor,
                "role": role,
                "event_ids": event_ids,
                "basis": basis,
                "role_scope": "DEPRECATED_ASSOCIATION_ONLY: roles imply neither blame nor authenticated identity",
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
        if not event.expected or any(c["status"] == "NOT_OBSERVED" for c in comparisons(event)):
            gaps.append(
                {
                    "type": "UNASSESSED_EVENT",
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "actor": event.actor,
                    "basis": "event lacks expected-state assertions or required observations",
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
