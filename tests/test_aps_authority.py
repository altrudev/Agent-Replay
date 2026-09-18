from __future__ import annotations

import pytest

from agent_replay.aps import APS_FIXTURE_REVISION, reconstruct_aps_fixture


ACTION_REF = "09a5166c3d75dbe76b76017e9d7197a67a1d3a2803ca86cf9aaea33f784537f5"


def fixture(
    name: str,
    expected: str,
    reasons: list[str] | None = None,
    sub_results: list[str] | None = None,
    *,
    policy_verdict: str = "permit",
) -> dict:
    return {
        "fixture": name,
        "expected": expected,
        "expectReasons": reasons or [],
        "expected_sub_results": sub_results or [],
        "envelope": {
            "intent": {
                "receipt_type": "aps:action-intent:v1",
                "issuer": "did:aps:insight-agent-001",
                "subject_agent": "did:aps:insight-agent-001",
                "action_ref": ACTION_REF,
                "delegation_ref": "sha256:leaf",
                "receipt_id": "intent-receipt",
                "signatures": [
                    {
                        "signer": "did:aps:insight-agent-001",
                        "alg": "Ed25519",
                        "value": "fixture-signature",
                    }
                ],
            },
            "decision": {
                "receipt_type": "aps:policy-decision:v1",
                "issuer": "did:aps:insight-gateway-001",
                "subject_agent": "did:aps:insight-agent-001",
                "action_ref": ACTION_REF,
                "delegation_ref": "sha256:leaf",
                "prev": "intent-receipt",
                "result": {"verdict": policy_verdict, "reason": "fixture"},
                "signatures": [
                    {
                        "signer": "did:aps:insight-gateway-001",
                        "alg": "Ed25519",
                        "value": "fixture-signature",
                    }
                ],
            },
            "delegations": [
                {
                    "delegation_id": "sha256:root",
                    "parent_delegation_id": None,
                    "issuer": "did:aps:insight-principal-001",
                    "subject": "did:aps:insight-agent-001",
                    "authority": {
                        "time": {
                            "not_before": "2026-08-25T00:00:00.000Z",
                            "not_after": "2026-08-26T00:00:00.000Z",
                        }
                    },
                },
                {
                    "delegation_id": "sha256:leaf",
                    "parent_delegation_id": "sha256:root",
                    "issuer": "did:aps:insight-agent-001",
                    "subject": "did:aps:insight-agent-001",
                    "authority": {
                        "time": {
                            "not_before": "2026-08-25T00:00:00.000Z",
                            "not_after": "2026-08-25T01:00:00.000Z",
                        }
                    },
                },
            ],
        },
    }


@pytest.mark.parametrize(
    ("name", "expected", "reasons", "sub_results", "policy_verdict", "authority_status"),
    [
        ("pass", "allowed", [], [], "permit", "VALID"),
        ("caution", "allowed", [], [], "permit", "VALID"),
        ("danger", "halt", ["HALT_VERDICT_DANGER"], [], "permit", "NOT_ESTABLISHED"),
        ("block", "halt", ["HALT_VERDICT_BLOCK"], [], "permit", "NOT_ESTABLISHED"),
        (
            "expired-oracle",
            "halt",
            ["HALT_ORACLE_EVIDENCE", "EXPIRED"],
            [],
            "permit",
            "NOT_ESTABLISHED",
        ),
        (
            "tampered-oracle",
            "halt",
            ["HALT_ORACLE_EVIDENCE", "UID_MISMATCH"],
            ["oracle_input_rebuild_differs", "rebuild_digest_equals_declared"],
            "permit",
            "NOT_ESTABLISHED",
        ),
        (
            "wrong-signer",
            "halt",
            ["HALT_ORACLE_EVIDENCE", "SIGNATURE_INVALID"],
            ["attester_address_mismatch"],
            "permit",
            "NOT_ESTABLISHED",
        ),
        (
            "authority-denied",
            "halt",
            ["HALT_AUTHORITY", "POLICY_DENIED"],
            [],
            "deny",
            "DENIED",
        ),
        (
            "sig-tampered",
            "halt",
            ["HALT_AUTHORITY", "SIGNATURE_INVALID"],
            ["decision_signature_invalid"],
            "permit",
            "UNVERIFIED",
        ),
        (
            "digest-mismatch",
            "halt",
            ["HALT_ORACLE_EVIDENCE", "EVIDENCE_DIGEST_MISMATCH"],
            ["evidence_digest_mismatch"],
            "permit",
            "NOT_ESTABLISHED",
        ),
        (
            "evidence-missing",
            "halt",
            ["HALT_ORACLE_EVIDENCE", "EVIDENCE_MISSING"],
            ["evidence_ref_absent"],
            "permit",
            "NOT_ESTABLISHED",
        ),
        (
            "delegation-expired",
            "halt",
            ["HALT_AUTHORITY", "AUTH_DELEGATION_EXPIRED"],
            [],
            "permit",
            "EXPIRED",
        ),
        (
            "delegation-revoked",
            "halt",
            ["HALT_AUTHORITY", "AUTH_DELEGATION_REVOKED"],
            [],
            "permit",
            "REVOKED",
        ),
    ],
)
def test_pinned_aps_case_matrix_preserves_authority_boundaries(
    name,
    expected,
    reasons,
    sub_results,
    policy_verdict,
    authority_status,
):
    report = reconstruct_aps_fixture(
        fixture(
            name,
            expected,
            reasons,
            sub_results,
            policy_verdict=policy_verdict,
        )
    )

    assert report["source"]["pinned_revision"] == APS_FIXTURE_REVISION
    assert report["source"]["fixture"] == name
    assert report["source"]["external_conformance_outcome"] == expected

    assert report["identity"]["claimed_actor"] == "did:aps:insight-agent-001"
    assert report["identity"]["intent_signer"] == "did:aps:insight-agent-001"
    assert report["identity"]["intent_authentication"] == "CONSISTENT_WITH_FIXTURE"

    assert report["authority"]["root_principal"] == "did:aps:insight-principal-001"
    assert report["authority"]["status"] == authority_status
    assert len(report["authority"]["delegation_path"]) == 2

    assert report["policy"]["issuer"] == "did:aps:insight-gateway-001"
    assert report["policy"]["verdict"] == policy_verdict
    if name == "sig-tampered":
        assert report["policy"]["authentication"] == "FAILED_BY_FIXTURE_ORACLE"
    else:
        assert report["policy"]["authentication"] == "CONSISTENT_WITH_FIXTURE"

    assert report["action_binding"]["matched"] is True

    # Critical Replay invariant: the fixture ends pre-dispatch. A permit is
    # authority evidence, never execution evidence.
    assert report["observed_execution"] == []
    assert report["execution_status"] == "NOT_OBSERVED"
    assert report["evidence_boundary"]["permit_is_execution"] is False


def test_permit_does_not_upgrade_actor_to_executor():
    report = reconstruct_aps_fixture(fixture("pass", "allowed"))

    assert report["policy"]["verdict"] == "permit"
    assert report["authority"]["status"] == "VALID"
    assert report["execution_status"] == "NOT_OBSERVED"
    assert any(
        "dispatched or executed" in statement
        for statement in report["evidence_boundary"]["cannot_establish"]
    )


def test_explicit_post_execution_evidence_is_required_before_execution_is_observed():
    document = fixture("synthetic-post-execution", "allowed")
    document["envelope"]["execution_events"] = [
        {
            "event_id": "execution-1",
            "actor": "did:aps:insight-agent-001",
            "action_ref": ACTION_REF,
            "status": "completed",
        }
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "OBSERVED"
    assert len(report["observed_execution"]) == 1


def test_action_ref_mismatch_is_preserved_not_inferred_away():
    document = fixture("binding-mismatch", "halt")
    document["envelope"]["decision"]["action_ref"] = "different-action"

    report = reconstruct_aps_fixture(document)

    assert report["action_binding"]["matched"] is False


def test_missing_envelope_fails_closed():
    with pytest.raises(ValueError, match="envelope"):
        reconstruct_aps_fixture({"fixture": "broken"})



def test_cli_reconstructs_aps_json_in_plain_language(tmp_path, monkeypatch, capsys):
    import json
    import sys

    from agent_replay import cli

    source = tmp_path / "aps.json"
    source.write_text(json.dumps(fixture("pass", "allowed")), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-replay", "reconstruct", str(source), "--format", "aps"],
    )

    cli.main()

    output = capsys.readouterr().out
    assert "AGENT REPLAY APS AUTHORITY RECONSTRUCTION" in output
    assert "Claimed actor: did:aps:insight-agent-001" in output
    assert "Authority status: VALID" in output
    assert "Status: NOT_OBSERVED" in output
    assert "Permit is execution: false" in output


def test_cli_auto_detects_aps_envelope(tmp_path):
    import json
    from argparse import Namespace
    from agent_replay import cli

    source = tmp_path / "aps.json"
    source.write_text(json.dumps(fixture("pass", "allowed")), encoding="utf-8")
    args = Namespace(
        input=str(source),
        format="auto",
        trace_id=None,
        max_bytes=1024 * 1024,
        max_events=100,
        max_parents=10,
        max_depth=10,
    )

    report = cli._reconstruct_input(args)

    assert report["input_format"] == "aps-oracle-safety-check-v1"
    assert report["execution_status"] == "NOT_OBSERVED"
    assert len(report["input_sha256"]) == 64
