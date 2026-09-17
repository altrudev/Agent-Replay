import json

import pytest

from agent_replay.share import build_share_bundle, sanitize_radial


def _incident():
    return {
        "schema": "agent-replay.incident.v2",
        "input_sha256": "a" * 64,
        "canonical_sha256": "b" * 64,
        "event_count": 2,
        "expectation_coverage": {
            "status": "COMPLETE",
            "events_with_expectations": 2,
            "total_events": 2,
            "ratio": 1.0,
            "claim": "No divergence can be established for events lacking expected-state evidence.",
        },
        "expectation_scope": "CALLER_SUPPLIED_ASSERTIONS",
        "timeline": [
            {
                "event_id": "approval-prod-west", "timestamp": "2026-09-17T00:00:00Z",
                "actor": "internal-approval-service", "kind": "approval.internal.v7", "status": "VALID",
                "parent_ids": [], "evidence": {"token": "super-secret", "internal_path": "/home/ubuntu/private"},
                "mismatches": [],
            },
            {
                "event_id": "execute-prod-west", "timestamp": "2026-09-17T00:00:01Z",
                "actor": "payment-agent", "kind": "execution.internal.v9", "status": "DIVERGENT",
                "parent_ids": ["approval-prod-west"], "evidence": {"approval_id": "private-id"},
                "mismatches": [{"field": "internal_execution_gate", "expected": False, "observed": True}],
            },
        ],
        "first_provable_divergence": {
            "event_id": "execute-prod-west", "timestamp": "2026-09-17T00:00:01Z",
            "actor": "payment-agent", "kind": "execution.internal.v9", "parent_ids": ["approval-prod-west"],
            "evidence": {"approval_id": "private-id"},
            "mismatches": [{"field": "internal_execution_gate", "expected": False, "observed": True}],
        },
        "divergences": [{
            "event_id": "execute-prod-west", "timestamp": "2026-09-17T00:00:01Z", "actor": "payment-agent",
            "kind": "execution.internal.v9", "parent_ids": ["approval-prod-west"], "evidence": {"approval_id": "private-id"},
            "mismatches": [{"field": "internal_execution_gate", "expected": False, "observed": True}],
        }],
        "causal_chain": [{
            "event_id": "execute-prod-west", "timestamp": "2026-09-17T00:00:01Z", "kind": "execution.internal.v9",
            "actor": "payment-agent", "relationship": "ROOT_DIVERGENCE", "direct_parent_ids": ["approval-prod-west"],
            "divergent_ancestor_ids": [],
        }],
        "attribution": [{"actor": "payment-agent", "role": "PRIMARY", "event_ids": ["execute-prod-west"], "basis": "actor owns the earliest provable divergence"}],
        "attribution_scope": "EVIDENCE_LABELS_ONLY", "confidence": "HIGH", "confidence_scope": "STRUCTURAL_ONLY",
        "evidence_gaps": [{
            "type": "UNASSESSED_EVENT", "event_id": "approval-prod-west", "kind": "approval.internal.v7",
            "actor": "internal-approval-service", "basis": "internal proprietary gap explanation",
            "effect": "internal proprietary effect explanation",
        }],
        "evidence_completeness": "INCOMPLETE", "evidence_completeness_scope": "STRUCTURAL_ONLY",
        "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
    }


def test_share_bundle_omits_raw_and_semantic_identifiers():
    bundle = build_share_bundle(_incident(), agent_replay_commit="abc123")
    encoded = json.dumps(bundle)
    forbidden = (
        "super-secret", "/home/ubuntu/private", "internal-approval-service", "payment-agent",
        "approval-prod-west", "execute-prod-west", "approval.internal.v7", "execution.internal.v9",
        "internal_execution_gate", "internal proprietary gap explanation", "internal proprietary effect explanation",
    )
    for value in forbidden:
        assert value not in encoded
    assert "actor-1" in encoded and "actor-2" in encoded
    assert "event-1" in encoded and "event-2" in encoded
    assert "kind-1" in encoded and "kind-2" in encoded
    assert "assertion-1" in encoded
    assert bundle["sharing_policy"]["allowlist_export"] is True
    assert bundle["sharing_policy"]["assertion_values_included"] is False
    assert bundle["incident"]["timeline"][1]["mismatches"][0]["expected_type"] == "boolean"
    assert "expected" not in bundle["incident"]["timeline"][1]["mismatches"][0]
    assert len(bundle["bundle_sha256"]) == 64


def test_values_require_explicit_opt_in_and_still_fail_sensitive_scan():
    incident = _incident()
    incident["timeline"][1]["mismatches"][0]["observed"] = "Bearer abc.def.ghi"
    default_bundle = build_share_bundle(incident)
    assert "Bearer abc.def.ghi" not in json.dumps(default_bundle)
    with pytest.raises(ValueError, match="sensitive-data scan"):
        build_share_bundle(incident, include_values=True)


def test_radial_export_is_aggregate_only():
    public = sanitize_radial({
        "engine": "ddc-radial-frequency/1.0",
        "engine_source": {"sha256": "c" * 64, "path": "/home/ubuntu/src/ddc/src/radial_frequency_v10.py"},
        "authoritative": False, "disposition": "CANDIDATE_FINDINGS", "examined_nodes": 5, "examined_edges": 5,
        "mapping_provenance": {"EXPLICIT": 2, "INFERRED": 3, "DEFAULT": 9},
        "hypotheses": [
            {"prior_id": "private-prior-id", "title": "Private Prior Title", "score": 0.85,
             "subjects": ["approval-prod-west", "execute-prod-west"], "features": {"private_feature": 0.4},
             "falsification_test": "private falsification logic", "rationale": "private rationale", "disposition": "CANDIDATE"},
            {"prior_id": "private-prior-id", "title": "Private Prior Title", "score": 0.90,
             "subjects": ["x", "y"], "features": {"private_feature": 0.9},
             "falsification_test": "private falsification logic", "rationale": "private rationale", "disposition": "CANDIDATE"},
        ],
    })
    encoded = json.dumps(public)
    for value in ("ddc-radial-frequency", "/home/ubuntu", "private-prior-id", "Private Prior Title", "approval-prod-west", "private_feature", "private falsification logic", "private rationale", '"score"'):
        assert value not in encoded
    assert public["engine_sha256"] == "c" * 64
    assert public["candidate_count"] == 2
    assert public["candidate_class_count"] == 1
    assert public["mapping_provenance"]["DEFAULT"] == 9
