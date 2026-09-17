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


def _trace_fingerprints(incident: dict[str, Any]) -> tuple[str | None, str | None]:
    trace = incident.get("trace_evidence")
    if not isinstance(trace, dict):
        return None, None
    return trace.get("record_sha256"), trace.get("trusted_key_sha256")


def compare_reconstruction(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    expected_trace_record, expected_trace_key = _trace_fingerprints(expected)
    observed_trace_record, observed_trace_key = _trace_fingerprints(observed)
    expected_has_trace = isinstance(expected.get("trace_evidence"), dict)
    observed_has_trace = isinstance(observed.get("trace_evidence"), dict)

    checks = {
        "canonical_sha256": expected.get("canonical_sha256") == observed.get("canonical_sha256"),
        "event_count": expected.get("event_count") == observed.get("event_count"),
        "reconstruction_status": expected.get("reconstruction_status") == observed.get("reconstruction_status"),
        "first_provable_divergence": _first_id(expected) == _first_id(observed),
        "causal_chain": _chain_signature(expected) == _chain_signature(observed),
        "trace_evidence_presence": expected_has_trace == observed_has_trace,
    }

    if expected_has_trace and observed_has_trace:
        checks["trace_record_sha256"] = expected_trace_record == observed_trace_record
        checks["trace_trusted_key_sha256"] = expected_trace_key == observed_trace_key

    expected_bundle = expected.get("supplementary_evidence_bundle_sha256")
    observed_bundle = observed.get("supplementary_evidence_bundle_sha256")
    if expected_bundle is not None or observed_bundle is not None:
        checks["supplementary_evidence_bundle_sha256"] = expected_bundle == observed_bundle

    differences = sorted(key for key, passed in checks.items() if not passed)
    core_keys = {
        "canonical_sha256",
        "event_count",
        "reconstruction_status",
        "first_provable_divergence",
        "causal_chain",
    }
    core_reproduced = all(checks[key] for key in core_keys)
    supplementary_missing = expected_has_trace and not observed_has_trace

    if not differences:
        status = "REPRODUCED"
    elif core_reproduced and supplementary_missing:
        status = "INCOMPLETE"
    else:
        status = "DRIFTED"

    return {
        "schema": "agent-replay.reproducibility.v1",
        "status": status,
        "evidence_scope": "CORE_PLUS_TRACE" if expected_has_trace else "CORE_ONLY",
        "core_reproduced": core_reproduced,
        "supplementary_evidence": (
            "NOT_REPRODUCED" if supplementary_missing else
            "REPRODUCED" if expected_has_trace and not any(
                key in differences for key in (
                    "trace_evidence_presence",
                    "trace_record_sha256",
                    "trace_trusted_key_sha256",
                    "supplementary_evidence_bundle_sha256",
                )
            ) else
            "NOT_APPLICABLE" if not expected_has_trace else
            "DRIFTED"
        ),
        "checks": checks,
        "differences": differences,
        "expected_canonical_sha256": expected.get("canonical_sha256"),
        "observed_canonical_sha256": observed.get("canonical_sha256"),
    }
