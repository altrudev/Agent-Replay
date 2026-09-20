from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from agent_replay import cli
from agent_replay.aps import (
    APS_FIXTURE_REPOSITORY,
    APS_FIXTURE_REVISION,
    reconstruct_aps_fixture,
)
from agent_replay.share import build_share_bundle


FIXTURE_DIR = Path("tests/fixtures/aps-oracle-safety-check-v1")
SCHEMA_DIR = Path("schemas")

EXPECTED = {
    "pass": ("allowed", "SUPPLIED_ALLOWED", "permit"),
    "caution": ("allowed", "SUPPLIED_ALLOWED", "permit"),
    "danger": ("halt", "NOT_ESTABLISHED", "permit"),
    "block": ("halt", "NOT_ESTABLISHED", "permit"),
    "expired-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "tampered-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "wrong-signer": ("halt", "NOT_ESTABLISHED", "permit"),
    "authority-denied": ("halt", "SUPPLIED_DENIED", "deny"),
    "sig-tampered": ("halt", "SUPPLIED_SIGNATURE_INVALID", "permit"),
    "digest-mismatch": ("halt", "NOT_ESTABLISHED", "permit"),
    "evidence-missing": ("halt", "NOT_ESTABLISHED", "permit"),
    "delegation-expired": ("halt", "SUPPLIED_EXPIRED", "permit"),
    "delegation-revoked": ("halt", "SUPPLIED_REVOKED", "permit"),
}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def test_vendored_fixtures_match_pinned_upstream_blob_hashes():
    source = json.loads((FIXTURE_DIR / "SOURCE.json").read_text(encoding="utf-8"))
    assert source["repository"] == APS_FIXTURE_REPOSITORY
    assert source["revision"] == APS_FIXTURE_REVISION
    assert set(source["git_blob_sha1"]) == {f"{name}.json" for name in EXPECTED}
    for filename, expected_sha in source["git_blob_sha1"].items():
        data = (FIXTURE_DIR / filename).read_bytes()
        assert _git_blob_sha1(data) == expected_sha


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_pinned_fixture_matrix_preserves_evidence_boundaries(name: str):
    document = load_fixture(name)
    raw = (FIXTURE_DIR / f"{name}.json").read_bytes()
    outcome, authority_status, policy_verdict = EXPECTED[name]

    report = reconstruct_aps_fixture(
        document,
        input_sha256=hashlib.sha256(raw).hexdigest(),
    )

    assert report["schema"] == "agent-replay.aps-authority-reconstruction.v2"
    assert report["adapter_validation"]["repository"] == APS_FIXTURE_REPOSITORY
    assert report["adapter_validation"]["revision"] == APS_FIXTURE_REVISION
    assert report["input_provenance"]["provenance_status"] == "UNKNOWN"

    assert report["external_conformance"]["outcome"] == outcome
    assert report["external_conformance"]["authority_status"] == authority_status
    assert report["policy"]["verdict"] == policy_verdict

    assert report["identity"]["claimed_actor"] == "did:aps:insight-agent-001"
    assert report["identity"]["independent_authentication"] == "NOT_VERIFIED"
    assert report["authority"]["root_principal"] == "did:aps:insight-principal-001"
    assert report["authority"]["independent_cryptographic_verification"] == "NOT_VERIFIED"

    assert report["binding"]["status"] == "COMPLETE"
    assert all(report["binding"]["checks"].values())

    assert report["execution_status"] == "NO_EXECUTION_EVIDENCE"
    assert report["observed_execution"] == []
    assert report["evidence_boundary"]["permit_is_execution"] is False
    assert report["evidence_boundary"]["external_conformance_is_replay_verification"] is False


def test_adapter_validation_revision_is_not_input_provenance():
    report = reconstruct_aps_fixture(load_fixture("pass"))

    assert report["adapter_validation"]["revision"] == APS_FIXTURE_REVISION
    assert report["input_provenance"]["revision"] is None
    assert "not the provenance" in report["adapter_validation"]["claim"]


def test_caller_supplied_input_provenance_is_kept_separate():
    document = load_fixture("pass")
    document["_agent_replay_source"] = {
        "repository": "example/repo",
        "revision": "abc123",
        "path": "fixture.json",
    }
    report = reconstruct_aps_fixture(document)

    assert report["input_provenance"] == {
        "repository": "example/repo",
        "revision": "abc123",
        "path": "fixture.json",
        "provenance_status": "CALLER_SUPPLIED",
    }
    assert report["adapter_validation"]["revision"] == APS_FIXTURE_REVISION


def test_broken_receipt_and_delegation_binding_is_not_hidden():
    document = load_fixture("pass")
    document["envelope"]["decision"]["action_ref"] = "other-action"
    document["envelope"]["decision"]["prev"] = "other-receipt"
    document["envelope"]["decision"]["delegation_ref"] = "sha256:other"

    report = reconstruct_aps_fixture(document)

    assert report["binding"]["status"] == "PARTIAL"
    assert report["binding"]["checks"]["action_ref"] is False
    assert report["binding"]["checks"]["receipt_link"] is False
    assert report["binding"]["checks"]["delegation_ref"] is False
    assert report["binding"]["checks"]["delegation_chain"] is True


def test_broken_delegation_chain_is_detected():
    document = load_fixture("pass")
    document["envelope"]["delegations"][1]["parent_delegation_id"] = "sha256:not-parent"

    report = reconstruct_aps_fixture(document)

    assert report["binding"]["checks"]["delegation_chain"] is False
    assert report["binding"]["status"] == "PARTIAL"


def test_random_execution_event_is_unbound_not_observed():
    document = load_fixture("pass")
    document["envelope"]["execution_events"] = [{"anything": "anything"}]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_UNBOUND"
    assert report["observed_execution"] == []
    assert len(report["execution"]["unbound_events"]) == 1


def test_execution_requires_action_binding_and_actor_consistency():
    document = load_fixture("pass")
    action_ref = document["envelope"]["intent"]["action_ref"]
    actor = document["envelope"]["intent"]["subject_agent"]
    document["envelope"]["execution_events"] = [
        {
            "event_id": "execution-1",
            "actor": actor,
            "action_ref": action_ref,
            "status": "completed",
        }
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_BOUND_TO_ACTION"
    assert len(report["observed_execution"]) == 1
    assert report["execution"]["independent_authentication"] == "NOT_VERIFIED"


def test_wrong_actor_execution_is_unbound():
    document = load_fixture("pass")
    document["envelope"]["execution_events"] = [
        {
            "event_id": "execution-1",
            "actor": "did:aps:someone-else",
            "action_ref": document["envelope"]["intent"]["action_ref"],
        }
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_UNBOUND"
    assert report["observed_execution"] == []


def test_aps_output_conforms_to_public_schema():
    report = reconstruct_aps_fixture(load_fixture("pass"))
    schema = json.loads(
        (SCHEMA_DIR / "aps-authority-reconstruction-v2.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_aps_safe_share_conforms_and_omits_raw_evidence():
    report = reconstruct_aps_fixture(load_fixture("pass"), input_sha256="a" * 64)
    bundle = build_share_bundle(report)
    public = bundle["incident"]
    schema = json.loads(
        (SCHEMA_DIR / "public-aps-share-v1.schema.json").read_text(encoding="utf-8")
    )

    jsonschema.Draft202012Validator(schema).validate(public)
    assert public["schema"] == "agent-replay.public-aps-share.v1"
    assert public["execution"]["bound_event_count"] == 0
    assert public["execution"]["partially_bound_event_count"] == 0
    assert public["execution"]["external_effect_proof"] is False
    assert "delegation_path" not in public["authority"]
    assert "events" not in public["execution"]


def test_aps_share_rejects_include_values():
    report = reconstruct_aps_fixture(load_fixture("pass"))
    with pytest.raises(ValueError, match="not applicable"):
        build_share_bundle(report, include_values=True)


def test_cli_reconstructs_real_aps_fixture(tmp_path, monkeypatch, capsys):
    output = tmp_path / "incident.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-replay",
            "reconstruct",
            str(FIXTURE_DIR / "pass.json"),
            "--format",
            "aps",
            "--json",
            "-o",
            str(output),
        ],
    )

    cli.main()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == "agent-replay.aps-authority-reconstruction.v2"
    assert report["binding"]["status"] == "COMPLETE"
    assert report["execution_status"] == "NO_EXECUTION_EVIDENCE"
    assert len(report["input_sha256"]) == 64
    assert capsys.readouterr().err == ""



def test_malformed_execution_entries_fail_closed_as_unbound_evidence():
    document = load_fixture("pass")
    document["envelope"]["execution_events"] = ["not-an-object"]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_UNBOUND"
    assert report["observed_execution"] == []
    assert report["execution"]["malformed_event_count"] == 1


def test_malformed_delegation_entries_are_rejected():
    document = load_fixture("pass")
    document["envelope"]["delegations"].append("not-an-object")

    with pytest.raises(ValueError, match="delegations must contain only objects"):
        reconstruct_aps_fixture(document)



def test_signature_failure_language_does_not_claim_independent_oracle_verification():
    report = reconstruct_aps_fixture(load_fixture("sig-tampered"))
    assert report["policy"]["signature_assessment"] == "FAILED_BY_SUPPLIED_CONFORMANCE"
    assert report["policy"]["independent_authentication"] == "NOT_VERIFIED"



def test_cli_auto_detects_real_aps_fixture(tmp_path):
    from argparse import Namespace

    args = Namespace(
        input=str(FIXTURE_DIR / "pass.json"),
        format="auto",
        trace_id=None,
        max_bytes=1024 * 1024,
        max_events=100,
        max_parents=10,
        max_depth=10,
    )

    report = cli._reconstruct_input(args)

    assert report["input_format"] == "aps-oracle-safety-check-v1"
    assert report["schema"] == "agent-replay.aps-authority-reconstruction.v2"


def test_plain_text_render_keeps_external_and_replay_status_separate():
    from agent_replay.report import render_text

    text = render_text(reconstruct_aps_fixture(load_fixture("pass")))
    assert "EXTERNAL APS CONFORMANCE" in text
    assert "Authority status: SUPPLIED_ALLOWED" in text
    assert "Independent authentication: NOT_VERIFIED" in text
    assert "Status: NO_EXECUTION_EVIDENCE" in text
    assert "Permit is execution: false" in text


def test_aps_public_share_redacts_free_form_external_strings():
    document = load_fixture("pass")
    document["expectReasons"] = ["user@example.com should never leak"]
    document["envelope"]["decision"]["result"]["verdict"] = "permit with free text"
    report = reconstruct_aps_fixture(document, input_sha256="b" * 64)

    public = build_share_bundle(report)["incident"]

    assert public["external_conformance"]["reason_codes"] == ["[REDACTED_TOKEN]"]
    assert public["policy"]["verdict"] == "[REDACTED_TOKEN]"
    assert "user@example.com" not in json.dumps(public)



def test_missing_actor_with_matching_action_ref_is_only_partially_bound():
    document = load_fixture("pass")
    document["envelope"]["execution_events"] = [
        {
            "event_id": "execution-actor-missing",
            "action_ref": document["envelope"]["intent"]["action_ref"],
            "status": "completed",
        }
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_PARTIALLY_BOUND"
    assert report["observed_execution"] == []
    assert report["execution"]["bound_events"] == []
    assert len(report["execution"]["partially_bound_events"]) == 1
    assert report["execution"]["external_effect_proof"] is False


def test_aps_action_result_without_actor_remains_partially_bound():
    document = load_fixture("pass")
    decision = document["envelope"]["decision"]
    document["envelope"]["action_result"] = {
        "artifact_type": "aps:action-result:v1",
        "receipt_id": "sha256:action-result-1",
        "issuer": "did:aps:gateway-001",
        "action_ref": document["envelope"]["intent"]["action_ref"],
        "prev": decision["receipt_id"],
        "decision_ref": "sha256:decision-material",
        "result": {
            "status": "completed",
            "effect_ref": "effect-123",
            "error_code": None,
        },
    }

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_PARTIALLY_BOUND"
    assert report["observed_execution"] == []
    assert len(report["execution"]["partially_bound_events"]) == 1
    event = report["execution"]["partially_bound_events"][0]
    assert event["evidence_kind"] == "APS_ACTION_RESULT"
    assert event["prev_matches_decision_receipt"] is True
    assert event["observation_scope"] == "ENFORCEMENT_BOUNDARY_POST_DISPATCH"
    assert event["external_effect_proof"] is False


def test_aps_action_result_can_be_fully_bound_when_actor_and_decision_link_match():
    document = load_fixture("pass")
    decision = document["envelope"]["decision"]
    document["envelope"]["action_result"] = {
        "artifact_type": "aps:action-result:v1",
        "receipt_id": "sha256:action-result-2",
        "issuer": "did:aps:gateway-001",
        "actor": document["envelope"]["intent"]["subject_agent"],
        "action_ref": document["envelope"]["intent"]["action_ref"],
        "prev": decision["receipt_id"],
        "decision_ref": "sha256:decision-material",
        "result": {"status": "completed"},
    }

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_BOUND_TO_ACTION"
    assert len(report["observed_execution"]) == 1
    assert report["observed_execution"][0]["evidence_kind"] == "APS_ACTION_RESULT"
    assert report["execution"]["external_effect_proof"] is False


def test_aps_action_result_wrong_prev_is_not_fully_bound():
    document = load_fixture("pass")
    document["envelope"]["action_result"] = {
        "artifact_type": "aps:action-result:v1",
        "receipt_id": "sha256:action-result-3",
        "actor": document["envelope"]["intent"]["subject_agent"],
        "action_ref": document["envelope"]["intent"]["action_ref"],
        "prev": "sha256:not-the-decision",
        "decision_ref": "sha256:decision-material",
        "result": {"status": "completed"},
    }

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_PARTIALLY_BOUND"
    assert report["observed_execution"] == []
    assert report["execution"]["partially_bound_events"][0]["prev_matches_decision_receipt"] is False


def test_aps_action_result_wrong_action_ref_is_unbound():
    document = load_fixture("pass")
    document["envelope"]["action_result"] = {
        "artifact_type": "aps:action-result:v1",
        "actor": document["envelope"]["intent"]["subject_agent"],
        "action_ref": "sha256:different-action",
        "prev": document["envelope"]["decision"]["receipt_id"],
        "decision_ref": "sha256:decision-material",
        "result": {"status": "completed"},
    }

    report = reconstruct_aps_fixture(document)

    assert report["execution_status"] == "EXECUTION_EVIDENCE_UNBOUND"
    assert report["observed_execution"] == []
    assert len(report["execution"]["unbound_events"]) == 1


def test_action_result_is_not_external_effect_proof():
    document = load_fixture("pass")
    document["envelope"]["action_result"] = {
        "artifact_type": "aps:action-result:v1",
        "actor": document["envelope"]["intent"]["subject_agent"],
        "action_ref": document["envelope"]["intent"]["action_ref"],
        "prev": document["envelope"]["decision"]["receipt_id"],
        "decision_ref": "sha256:decision-material",
        "result": {
            "status": "completed",
            "effect_ref": "effect-123",
        },
    }

    report = reconstruct_aps_fixture(document)

    assert report["execution"]["external_effect_proof"] is False
    assert any(
        "not proof that an external effect occurred or settled" in claim
        for claim in report["evidence_boundary"]["claims"]
    )
