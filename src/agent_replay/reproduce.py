from __future__ import annotations

from typing import Any


def _first_id(incident: dict[str, Any]) -> str | None:
    first = incident.get("first_provable_divergence")
    return first.get("event_id") if isinstance(first, dict) else None


def _chain_signature(incident: dict[str, Any]) -> list[tuple[str, str, tuple[str, ...]]]:
    out: list[tuple[str, str, tuple[str, ...]]] = []
    for item in incident.get("causal_chain") or []:
        if not isinstance(item, dict):
            continue
        out.append((
            str(item.get("event_id", "")),
            str(item.get("relationship", "")),
            tuple(str(x) for x in item.get("divergent_ancestor_ids") or []),
        ))
    return out


def compare_reconstruction(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "canonical_sha256": expected.get("canonical_sha256") == observed.get("canonical_sha256"),
        "event_count": expected.get("event_count") == observed.get("event_count"),
        "reconstruction_status": expected.get("reconstruction_status") == observed.get("reconstruction_status"),
        "first_provable_divergence": _first_id(expected) == _first_id(observed),
        "causal_chain": _chain_signature(expected) == _chain_signature(observed),
    }
    differences = sorted(key for key, passed in checks.items() if not passed)
    return {
        "schema": "agent-replay.reproducibility.v1",
        "status": "REPRODUCED" if not differences else "DRIFTED",
        "checks": checks,
        "differences": differences,
        "expected_canonical_sha256": expected.get("canonical_sha256"),
        "observed_canonical_sha256": observed.get("canonical_sha256"),
    }
