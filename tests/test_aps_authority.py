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
    "pass": ("allowed", "ALLOWED_BY_FIXTURE", "permit"),
    "caution": ("allowed", "ALLOWED_BY_FIXTURE", "permit"),
    "danger": ("halt", "NOT_ESTABLISHED", "permit"),
    "block": ("halt", "NOT_ESTABLISHED", "permit"),
    "expired-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "tampered-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "wrong-signer": ("halt", "NOT_ESTABLISHED", "permit"),
    "authority-denied": ("halt", "DENIED", "deny"),
    "sig-tampered": ("halt", "UNVERIFIED", "permit"),
    "digest-mismatch": ("halt", "NOT_ESTABLISHED", "permit"),
    "evidence-missing": ("halt", "NOT_ESTABLISHED", "permit"),
    "delegation-expired": ("halt", "EXPIRED", "permit"),
    "delegation-revoked": ("halt", "REVOKED", "permit"),
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

    assert report["execution_status"] == "EXECUTION_BOUND_TO_ACTION"
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
