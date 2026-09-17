from __future__ import annotations

from copy import deepcopy

from agent_replay.reproduce import compare_reconstruction


def _incident() -> dict:
    return {
        "canonical_sha256": "a" * 64,
        "event_count": 1,
        "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
        "first_provable_divergence": {"event_id": "event-1"},
        "causal_chain": [],
    }


def _with_trace(incident: dict) -> dict:
    value = deepcopy(incident)
    value["trace_evidence"] = {
        "record_sha256": "b" * 64,
        "trusted_key_sha256": "c" * 64,
    }
    value["supplementary_evidence_bundle_sha256"] = "d" * 64
    return value


def test_core_only_reproduction_remains_reproduced():
    expected = _incident()
    observed = deepcopy(expected)

    result = compare_reconstruction(expected, observed)

    assert result["status"] == "REPRODUCED"
    assert result["evidence_scope"] == "CORE_ONLY"
    assert result["supplementary_evidence"] == "NOT_APPLICABLE"


def test_trace_incident_without_trace_replay_is_incomplete_not_reproduced():
    expected = _with_trace(_incident())
    observed = _incident()

    result = compare_reconstruction(expected, observed)

    assert result["status"] == "INCOMPLETE"
    assert result["core_reproduced"] is True
    assert result["supplementary_evidence"] == "NOT_REPRODUCED"
    assert "trace_evidence_presence" in result["differences"]
    assert "supplementary_evidence_bundle_sha256" in result["differences"]


def test_trace_incident_with_same_trace_scope_is_reproduced():
    expected = _with_trace(_incident())
    observed = deepcopy(expected)

    result = compare_reconstruction(expected, observed)

    assert result["status"] == "REPRODUCED"
    assert result["evidence_scope"] == "CORE_PLUS_TRACE"
    assert result["supplementary_evidence"] == "REPRODUCED"
    assert result["checks"]["trace_record_sha256"] is True
    assert result["checks"]["trace_trusted_key_sha256"] is True


def test_trace_record_drift_is_reported_as_drifted():
    expected = _with_trace(_incident())
    observed = deepcopy(expected)
    observed["trace_evidence"]["record_sha256"] = "e" * 64
    observed["supplementary_evidence_bundle_sha256"] = "f" * 64

    result = compare_reconstruction(expected, observed)

    assert result["status"] == "DRIFTED"
    assert result["core_reproduced"] is True
    assert result["supplementary_evidence"] == "DRIFTED"
    assert "trace_record_sha256" in result["differences"]
    assert "supplementary_evidence_bundle_sha256" in result["differences"]


def test_unexpected_trace_scope_is_drifted():
    expected = _incident()
    observed = _with_trace(_incident())

    result = compare_reconstruction(expected, observed)

    assert result["status"] == "DRIFTED"
    assert "trace_evidence_presence" in result["differences"]
