from __future__ import annotations

import hashlib
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


def reconstruct(path: str) -> dict[str, Any]:
    source = Path(path)
    events = normalize_jsonl(source)
    divergences = build_divergences(events)
    chain = causal_chain(events, divergences)

    return {
        "schema": "agent-replay.incident.v2",
        "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "event_count": len(events),
        "timeline": _timeline(events),
        "first_provable_divergence": divergences[0] if divergences else None,
        "divergences": divergences,
        "causal_chain": chain,
        "attribution": attribution(divergences, chain),
        "confidence": confidence(divergences, chain),
        "reproducibility": "CONFIRMED" if divergences else "NO_DIVERGENCE_FOUND",
    }
