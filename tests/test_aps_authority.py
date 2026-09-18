from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from agent_replay import cli
from agent_replay.aps import (
    APS_FIXTURE_REPOSITORY,
    APS_FIXTURE_REVISION,
    reconstruct_aps_fixture,
)


FIXTURE_ROOT = Path("tests/fixtures/aps/oracle-safety-check-v1")
ACTION_REF = "09a5166c3d75dbe76b76017e9d7197a67a1d3a2803ca86cf9aaea33f784537f5"

CASES = {
    "pass": ("allowed", "ALLOWED", "permit"),
    "caution": ("allowed", "ALLOWED", "permit"),
    "danger": ("halt", "NOT_ESTABLISHED", "permit"),
    "block": ("halt", "NOT_ESTABLISHED", "permit"),
    "expired-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "tampered-oracle": ("halt", "NOT_ESTABLISHED", "permit"),
    "wrong-signer": ("halt", "NOT_ESTABLISHED", "permit"),
    "authority-denied": ("halt", "DENIED", "deny"),
    "sig-tampered": ("halt", "SIGNATURE_INVALID", "permit"),
    "digest-mismatch": ("halt", "NOT_ESTABLISHED", "permit"),
    "evidence-missing": ("halt", "NOT_ESTABLISHED", "permit"),
    "delegation-expired": ("halt", "EXPIRED", "permit"),
    "delegation-revoked": ("halt", "REVOKED", "permit"),
}


def load_case(name: str) -> tuple[dict, bytes]:
    raw = (FIXTURE_ROOT / f"{name}.json").read_bytes()
    return json.loads(raw), raw


@pytest.mark.parametrize("name", sorted(CASES))
def test_real_pinned_aps_fixture_matrix_preserves_evidence_boundaries(name: str):
    document, raw = load_case(name)
    expected, external_disposition, policy_verdict = CASES[name]

    report = reconstruct_aps_fixture(
        document,
        input_sha256=hashlib.sha256(raw).hexdigest(),
        input_provenance={
            "repository": APS_FIXTURE_REPOSITORY,
            "revision": APS_FIXTURE_REVISION,
            "path": f"oracle-safety-check-v1/{name}.json",
        },
    )

    assert report["source"]["adapter_tested_against"]["revision"] == APS_FIXTURE_REVISION
    assert report["source"]["input_provenance"]["revision"] == APS_FIXTURE_REVISION
    assert report["source"]["input_provenance"]["provenance_status"] == "SUPPLIED"
    assert report["source"]["external_conformance"]["outcome"] == expected
    assert (
        report["source"]["external_conformance"]["authority_disposition"]
        == external_disposition
    )

    assert report["identity"]["claimed_actor"] == "did:aps:insight-agent-001"
    assert report["identity"]["intent_signer"] == "did:aps:insight-agent-001"
    assert (
        report["identity"]["intent_authentication"]
        == "CLAIM_CONSISTENT_NOT_CRYPTOGRAPHICALLY_VERIFIED"
    )

    assert report["authority"]["root_principal"] == "did:aps:insight-principal-001"
    assert report["authority"]["chain_continuity"] is True
    assert report["authority"]["evidence_status"] == "CHAIN_BOUND"
    assert (
        report["authority"]["replay_verification"]
        == "NOT_INDEPENDENTLY_CRYPTOGRAPHICALLY_VERIFIED"
    )
    assert len(report["authority"]["delegation_path"]) == 2

    assert report["policy"]["issuer"] == "did:aps:insight-gateway-001"
    assert report["policy"]["verdict"] == policy_verdict
    if name == "sig-tampered":
        assert report["policy"]["authentication"] == "FAILED_BY_EXTERNAL_CONFORMANCE"
    else:
        assert (
            report["policy"]["authentication"]
            == "CLAIM_CONSISTENT_NOT_CRYPTOGRAPHICALLY_VERIFIED"
        )

    assert report["binding"]["status"] == "COMPLETE"
    assert report["binding"]["action_ref"]["matched"] is True
    assert report["binding"]["receipt_link"]["matched"] is True
    assert report["binding"]["delegation_ref"]["matched"] is True
    assert report["binding"]["delegation_chain_continuity"] is True

    # Timo's fixture ends pre-dispatch. Permit is authority evidence only.
    assert report["execution"]["status"] == "NOT_OBSERVED"
    assert report["execution"]["evidence_count"] == 0
    assert report["execution"]["action_bound_count"] == 0
    assert report["execution"]["actor_bound_count"] == 0
    assert report["evidence_boundary"]["permit_is_execution"] is False


def test_adapter_test_revision_is_not_claimed_as_input_provenance():
    document, raw = load_case("pass")
    report = reconstruct_aps_fixture(
        document,
        input_sha256=hashlib.sha256(raw).hexdigest(),
    )

    assert report["source"]["adapter_tested_against"]["revision"] == APS_FIXTURE_REVISION
    assert report["source"]["input_provenance"]["revision"] is None
    assert report["source"]["input_provenance"]["provenance_status"] == "UNKNOWN"


def test_unbound_execution_evidence_does_not_become_observed_execution():
    document, _ = load_case("pass")
    document["envelope"]["execution_events"] = [{"event_id": "unrelated"}]

    report = reconstruct_aps_fixture(document)

    assert report["execution"]["status"] == "EVIDENCE_PRESENT_UNBOUND"
    assert report["execution"]["action_bound_count"] == 0
    assert report["execution"]["actor_bound_count"] == 0


def test_action_bound_execution_does_not_upgrade_actor():
    document, _ = load_case("pass")
    document["envelope"]["execution_events"] = [
        {"event_id": "x", "action_ref": ACTION_REF, "actor": "did:aps:other-agent"}
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution"]["status"] == "EVIDENCE_ACTION_BOUND"
    assert report["execution"]["action_bound_count"] == 1
    assert report["execution"]["actor_bound_count"] == 0


def test_actor_bound_execution_is_still_not_cryptographically_authenticated():
    document, _ = load_case("pass")
    document["envelope"]["execution_events"] = [
        {
            "event_id": "x",
            "action_ref": ACTION_REF,
            "actor": "did:aps:insight-agent-001",
        }
    ]

    report = reconstruct_aps_fixture(document)

    assert report["execution"]["status"] == "EVIDENCE_ACTOR_BOUND"
    assert report["execution"]["actor_bound_count"] == 1
    assert report["execution"]["cryptographic_authentication"] == "NOT_VERIFIED"


@pytest.mark.parametrize(
    "mutation",
    ("action_ref", "receipt_link", "delegation_ref", "delegation_chain"),
)
def test_broken_binding_is_preserved_as_partial(mutation: str):
    document, _ = load_case("pass")

    if mutation == "action_ref":
        document["envelope"]["decision"]["action_ref"] = "different-action"
    elif mutation == "receipt_link":
        document["envelope"]["decision"]["prev"] = "different-receipt"
    elif mutation == "delegation_ref":
        document["envelope"]["decision"]["delegation_ref"] = "different-delegation"
    else:
        document["envelope"]["delegations"][1]["parent_delegation_id"] = "different-parent"

    report = reconstruct_aps_fixture(document)

    assert report["binding"]["status"] == "PARTIAL"


def test_missing_envelope_fails_closed():
    with pytest.raises(ValueError, match="envelope"):
        reconstruct_aps_fixture({"fixture": "broken"})


def test_cli_reconstructs_real_aps_json_in_plain_language(monkeypatch, capsys):
    source = FIXTURE_ROOT / "pass.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-replay", "reconstruct", str(source), "--format", "aps"],
    )

    cli.main()

    output = capsys.readouterr().out
    assert "AGENT REPLAY APS AUTHORITY RECONSTRUCTION" in output
    assert "Input provenance: UNKNOWN" in output
    assert "Evidence status: CHAIN_BOUND" in output
    assert "Overall: COMPLETE" in output
    assert "Status: NOT_OBSERVED" in output
    assert "Permit is execution: false" in output


def test_cli_auto_detects_real_aps_envelope():
    from argparse import Namespace

    source = FIXTURE_ROOT / "pass.json"
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
    assert report["execution"]["status"] == "NOT_OBSERVED"
    assert report["source"]["input_provenance"]["sha256"] == report["input_sha256"]



def test_partial_input_provenance_stays_partial_and_unverified():
    document, raw = load_case("pass")
    report = reconstruct_aps_fixture(
        document,
        input_sha256=hashlib.sha256(raw).hexdigest(),
        input_provenance={"repository": APS_FIXTURE_REPOSITORY},
    )

    provenance = report["source"]["input_provenance"]
    assert provenance["provenance_status"] == "PARTIAL"
    assert provenance["revision"] is None
    assert provenance["verification"] == "CALLER_SUPPLIED_NOT_VERIFIED"


def test_cli_preserves_explicit_aps_provenance(monkeypatch):
    from argparse import Namespace

    source = FIXTURE_ROOT / "pass.json"
    args = Namespace(
        input=str(source),
        format="aps",
        trace_id=None,
        max_bytes=1024 * 1024,
        max_events=100,
        max_parents=10,
        max_depth=10,
        source_repository=APS_FIXTURE_REPOSITORY,
        source_revision=APS_FIXTURE_REVISION,
        source_path="fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1/pass.json",
    )

    report = cli._reconstruct_input(args)
    provenance = report["source"]["input_provenance"]

    assert provenance["provenance_status"] == "SUPPLIED"
    assert provenance["repository"] == APS_FIXTURE_REPOSITORY
    assert provenance["revision"] == APS_FIXTURE_REVISION
    assert provenance["verification"] == "CALLER_SUPPLIED_NOT_VERIFIED"
