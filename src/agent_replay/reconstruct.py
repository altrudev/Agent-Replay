from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .analyze import attribution, build_divergences, causal_chain, confidence, mismatches
from .normalize import normalize_jsonl


def _timeline(events):
    out = []
    for event in events:
        mm = mismatches(event)
        out.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "kind": event.kind,
                "status": "DIVERGENT" if mm else "VALID",
                "parent_ids": list(event.parent_ids),
                "source_line": event.source_line,
                "evidence": event.evidence,
                "mismatches": mm,
            }
        )
    return out


def _canonical_digest(events) -> str:
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


def reconstruct(path: str) -> dict[str, Any]:
    source = Path(path)
    events = normalize_jsonl(source)
    divergences = build_divergences(events)
    chain = causal_chain(events, divergences)

    return {
        "schema": "agent-replay.incident.v2",
        "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "canonical_sha256": _canonical_digest(events),
        "event_count": len(events),
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
        "reproducibility": "CONFIRMED" if divergences else "NO_DIVERGENCE_FOUND",
    }
