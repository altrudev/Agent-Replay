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
                "event_id": "approval",
                "timestamp": "2026-09-17T00:00:00Z",
                "actor": "internal-approval-service",
                "kind": "approval.issued",
                "status": "VALID",
                "parent_ids": [],
                "evidence": {"token": "super-secret", "internal_path": "/home/ubuntu/private"},
                "mismatches": [],
            },
            {
                "event_id": "execute",
                "timestamp": "2026-09-17T00:00:01Z",
                "actor": "payment-agent",
                "kind": "execution.attempted",
                "status": "DIVERGENT",
                "parent_ids": ["approval"],
                "evidence": {"approval_id": "private-id"},
                "mismatches": [{"field": "execution_permitted", "expected": False, "observed": True}],
            },
        ],
        "first_provable_divergence": {
            "event_id": "execute",
            "timestamp": "2026-09-17T00:00:01Z",
            "actor": "payment-agent",
            "kind": "execution.attempted",
            "parent_ids": ["approval"],
            "evidence": {"approval_id": "private-id"},
            "mismatches": [{"field": "execution_permitted", "expected": False, "observed": True}],
        },
        "divergences": [
            {
                "event_id": "execute",
                "timestamp": "2026-09-17T00:00:01Z",
                "actor": "payment-agent",
                "kind": "execution.attempted",
                "parent_ids": ["approval"],
                "evidence": {"approval_id": "private-id"},
                "mismatches": [{"field": "execution_permitted", "expected": False, "observed": True}],
            }
        ],
        "causal_chain": [
            {
                "event_id": "execute",
                "timestamp": "2026-09-17T00:00:01Z",
                "kind": "execution.attempted",
                "actor": "payment-agent",
                "relationship": "ROOT_DIVERGENCE",
                "direct_parent_ids": ["approval"],
                "divergent_ancestor_ids": [],
            }
        ],
        "attribution": [
            {
                "actor": "payment-agent",
                "role": "PRIMARY",
                "event_ids": ["execute"],
                "basis": "actor owns the earliest provable divergence",
            }
        ],
        "attribution_scope": "EVIDENCE_LABELS_ONLY",
        "confidence": "HIGH",
        "confidence_scope": "STRUCTURAL_ONLY",
        "evidence_gaps": [
            {
                "type": "UNASSESSED_EVENT",
                "event_id": "approval",
                "kind": "approval.issued",
                "actor": "internal-approval-service",
                "basis": "event has no caller-supplied expected-state assertion",
                "effect": "Agent Replay cannot establish validity or divergence for this event",
            }
        ],
        "evidence_completeness": "INCOMPLETE",
        "evidence_completeness_scope": "STRUCTURAL_ONLY",
        "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
    }


def test_share_bundle_omits_raw_evidence_paths_and_real_actor_labels():
    bundle = build_share_bundle(_incident(), agent_replay_commit="abc123")
    encoded = json.dumps(bundle)
    assert "super-secret" not in encoded
    assert "/home/ubuntu/private" not in encoded
    assert "internal-approval-service" not in encoded
    assert "payment-agent" not in encoded
    assert "actor-1" in encoded
    assert "actor-2" in encoded
    assert bundle["sharing_policy"]["allowlist_export"] is True
    assert len(bundle["bundle_sha256"]) == 64


def test_radial_export_omits_engine_path_features_and_scores():
    public = sanitize_radial({
        "engine": "ddc-radial-frequency/1.0",
        "engine_source": {"sha256": "c" * 64, "path": "/home/ubuntu/src/ddc/src/radial_frequency_v10.py"},
        "authoritative": False,
        "disposition": "CANDIDATE_FINDINGS",
        "examined_nodes": 5,
        "examined_edges": 5,
        "hypotheses": [
            {
                "prior_id": "toctou",
                "title": "Check/use temporal race",
                "score": 0.85,
                "subjects": ["approval", "execute"],
                "features": {"time_gap": 0.4},
                "falsification_test": "change state after validation",
                "rationale": "validation and effect are separated",
                "disposition": "CANDIDATE",
            }
        ],
    })
    encoded = json.dumps(public)
    assert "/home/ubuntu" not in encoded
    assert "features" not in encoded
    assert '"score"' not in encoded
    assert public["engine_sha256"] == "c" * 64
    assert public["hypotheses"][0]["prior_id"] == "toctou"


def test_sensitive_scan_fails_closed_if_allowlisted_text_contains_secret():
    incident = _incident()
    incident["attribution"][0]["basis"] = "Bearer abc.def.ghi"
    with pytest.raises(ValueError, match="sensitive-data scan"):
        build_share_bundle(incident)
