from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .analyze import (
    attribution,
    build_divergences,
    causal_chain,
    confidence,
    evidence_gaps,
    mismatches,
    not_observed,
)
from .model import CanonicalEvent
from .normalize import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_EVENTS,
    DEFAULT_MAX_PARENTS,
    normalize_jsonl,
    normalize_records,
)


def _timeline(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    out = []
    for event in events:
        mm = mismatches(event)
        missing = not_observed(event)
        if not event.expected:
            status = "UNASSESSED"
        elif mm:
            status = "DIVERGENT"
        elif missing:
            status = "UNASSESSED"
        else:
            status = "VALID"

        out.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "kind": event.kind,
                "status": status,
                "parent_ids": list(event.parent_ids),
                "source_line": event.source_line,
                "evidence": event.evidence,
                "mismatches": mm,
                "not_observed": missing,
            }
        )
    return out


def _canonical_digest(events: list[CanonicalEvent]) -> str:
    payload = [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "kind": event.kind,
            "observed": event.observed,
            "expected": event.expected,
            "evidence": event.evidence,
            "parent_ids": list(event.parent_ids),
        }
        for event in events
    ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _expectation_coverage(events: list[CanonicalEvent]) -> dict[str, Any]:
    comparable = sum(1 for event in events if event.expected)
    total = len(events)
    if total == 0:
        status = "NO_EVENTS"
    elif comparable == 0:
        status = "NO_EXPECTATIONS"
    elif comparable == total:
        status = "COMPLETE"
    else:
        status = "PARTIAL"

    return {
        "status": status,
        "events_with_expectations": comparable,
        "total_events": total,
        "ratio": round(comparable / total, 6) if total else 0.0,
        "claim": (
            "No divergence can be established for events lacking expected-state evidence."
        ),
    }


def reconstruct_events(
    events: list[CanonicalEvent],
    *,
    input_sha256: str,
) -> dict[str, Any]:
    divergences = build_divergences(events)
    chain = causal_chain(events, divergences)
    gaps = evidence_gaps(events, divergences, chain)

    return {
        "schema": "agent-replay.incident.v2",
        "input_sha256": input_sha256,
        "canonical_sha256": _canonical_digest(events),
        "event_count": len(events),
        "expectation_coverage": _expectation_coverage(events),
        "expectation_scope": (
            "CALLER_SUPPLIED_ASSERTIONS: expected-state values are supplied by "
            "the input evidence and are not independently authenticated by Agent Replay."
        ),
        "timeline": _timeline(events),
        "first_provable_divergence": divergences[0] if divergences else None,
        "divergences": divergences,
        "causal_chain": chain,
        "attribution": attribution(divergences, chain),
        "attribution_scope": (
            "EVIDENCE_LABELS_ONLY: actor identities are asserted by source evidence "
            "and are not independently authenticated by Agent Replay."
        ),
        "confidence": confidence(divergences, chain),
        "confidence_scope": (
            "STRUCTURAL_ONLY: confidence reflects mismatch and graph structure, "
            "not independent truth, identity, or policy provenance."
        ),
        "evidence_gaps": gaps,
        "evidence_completeness": (
            "INCOMPLETE" if gaps else "COMPLETE_FOR_SUPPLIED_ASSERTIONS"
        ),
        "evidence_completeness_scope": (
            "STRUCTURAL_ONLY: completeness describes supplied assertions and explicit "
            "causal links; it does not prove that all real-world telemetry was captured."
        ),
        "reproducibility": "NOT_TESTED",
        "reconstruction_status": (
            "DIVERGENCE_RECONSTRUCTED" if divergences else "NO_DIVERGENCE_ESTABLISHED"
        ),
    }


def reconstruct_records(
    records: Iterable[dict[str, Any]],
    *,
    input_sha256: str,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_parents: int = DEFAULT_MAX_PARENTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    events = normalize_records(
        records,
        max_events=max_events,
        max_parents=max_parents,
        max_depth=max_depth,
    )
    return reconstruct_events(events, input_sha256=input_sha256)


def reconstruct(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_parents: int = DEFAULT_MAX_PARENTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    source = Path(path)
    size = source.stat().st_size
    if size > max_bytes:
        from .normalize import EvidenceFormatError
        raise EvidenceFormatError(
            f"input size {size} exceeds max_bytes={max_bytes}"
        )
    raw = source.read_bytes()
    events = normalize_jsonl(
        source,
        max_bytes=max_bytes,
        max_events=max_events,
        max_parents=max_parents,
        max_depth=max_depth,
    )
    return reconstruct_events(
        events,
        input_sha256=hashlib.sha256(raw).hexdigest(),
    )
