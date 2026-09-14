from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .analyze import attribution, build_divergences, causal_chain, confidence
from .normalize import normalize_jsonl


def reconstruct(path: str) -> dict[str, Any]:
    source = Path(path)
    events = normalize_jsonl(source)
    divergences = build_divergences(events)
    chain = causal_chain(events, divergences)

    return {
        "schema": "agent-replay.incident.v2",
        "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "event_count": len(events),
        "first_provable_divergence": divergences[0] if divergences else None,
        "divergences": divergences,
        "causal_chain": chain,
        "attribution": attribution(divergences, chain),
        "confidence": confidence(divergences, chain),
        "reproducibility": "CONFIRMED" if divergences else "NO_DIVERGENCE_FOUND",
    }
