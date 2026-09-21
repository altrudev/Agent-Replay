from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_replay.aps import (
    APS_ACTION_RESULT_FIXTURE_FAMILY,
    APS_ACTION_RESULT_FIXTURE_REVISION,
    APS_FIXTURE_REPOSITORY,
    reconstruct_aps_action_result_case,
)


FIXTURE_DIR = Path("tests/fixtures/aps-action-result-binding")

EXPECTED_REPLAY = {
    "positive": "EXECUTION_EVIDENCE_BOUND_TO_ACTION",
    "subject-agent-absent": "EXECUTION_EVIDENCE_PARTIALLY_BOUND",
    "prev-not-the-decision": "EXECUTION_EVIDENCE_PARTIALLY_BOUND",
    "decision-ref-mismatch": "EXECUTION_EVIDENCE_PARTIALLY_BOUND",
    "action-ref-mismatch": "EXECUTION_EVIDENCE_UNBOUND",
    "subject-agent-changed": "EXECUTION_EVIDENCE_UNBOUND",
}


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_action_result_fixture_is_exactly_pinned_to_tima_revision():
    source = _load("SOURCE.json")
    assert source["repository"] == APS_FIXTURE_REPOSITORY
    assert source["revision"] == APS_ACTION_RESULT_FIXTURE_REVISION
    assert source["path"] == APS_ACTION_RESULT_FIXTURE_FAMILY

    for filename, expected_blob in source["git_blob_sha1"].items():
        assert _git_blob_sha1((FIXTURE_DIR / filename).read_bytes()) == expected_blob


@pytest.mark.parametrize("case_name", EXPECTED_REPLAY)
def test_pinned_action_result_cases_are_rederived_by_replay(case_name: str):
    chain_bytes = (FIXTURE_DIR / "chain.json").read_bytes()
    chain = json.loads(chain_bytes)
    report = reconstruct_aps_action_result_case(
        chain,
        case_name,
        input_sha256=hashlib.sha256(chain_bytes).hexdigest(),
    )

    assert report["execution_status"] == EXPECTED_REPLAY[case_name]
    assert report["adapter_validation"]["revision"] == APS_ACTION_RESULT_FIXTURE_REVISION
    assert report["adapter_validation"]["fixture_family"] == APS_ACTION_RESULT_FIXTURE_FAMILY
    assert report["input_provenance"]["revision"] == APS_ACTION_RESULT_FIXTURE_REVISION
    assert report["input_provenance"]["path"].endswith(f"chain.json#cases.{case_name}")
    assert report["external_conformance"]["source"] == "NOT_IMPORTED_FROM_VECTORS"
    assert report["external_conformance"]["outcome"] is None
    assert report["aps_receipt_schema_validation"] == "NOT_PERFORMED"
    assert report["execution"]["external_effect_proof"] is False


def test_positive_action_result_is_fully_bound_only_as_post_dispatch_observation():
    chain = _load("chain.json")
    report = reconstruct_aps_action_result_case(chain, "positive")

    assert len(report["observed_execution"]) == 1
    event = report["observed_execution"][0]
    assert event["evidence_kind"] == "APS_ACTION_RESULT"
    assert event["observation_scope"] == "ENFORCEMENT_BOUNDARY_POST_DISPATCH"
    assert event["prev_matches_decision_receipt"] is True
    assert event["decision_ref_matches_decision"] is True
    assert event["aps_receipt_schema_validation"] == "NOT_PERFORMED"
    assert event["external_effect_proof"] is False


def test_subject_agent_absent_resolves_to_partial_without_claiming_aps_schema_validity():
    chain = _load("chain.json")
    report = reconstruct_aps_action_result_case(chain, "subject-agent-absent")

    assert report["execution_status"] == "EXECUTION_EVIDENCE_PARTIALLY_BOUND"
    assert report["observed_execution"] == []
    assert len(report["execution"]["partially_bound_events"]) == 1
    event = report["execution"]["partially_bound_events"][0]
    assert event["actor"] is None
    assert event["aps_receipt_schema_validation"] == "NOT_PERFORMED"


def test_subject_agent_changed_resolves_to_unbound_as_replay_evidence_only():
    chain = _load("chain.json")
    report = reconstruct_aps_action_result_case(chain, "subject-agent-changed")

    assert report["execution_status"] == "EXECUTION_EVIDENCE_UNBOUND"
    assert report["observed_execution"] == []
    assert report["execution"]["partially_bound_events"] == []
    assert len(report["execution"]["unbound_events"]) == 1
    assert report["execution"]["unbound_events"][0]["actor"] == chain["identities"]["second_agent"]
    assert report["external_conformance"]["authority_status"] == "NOT_ESTABLISHED"


def test_vectors_are_context_not_an_oracle_for_replay_results():
    vectors = _load("vectors.json")
    chain = _load("chain.json")

    unresolved = {
        item["case"]
        for item in vectors["cases"]
        if item["replay_policy"]["status"] == "unresolved_until_run"
    }
    assert unresolved == {"subject-agent-absent", "subject-agent-changed"}

    actual = {
        case_name: reconstruct_aps_action_result_case(chain, case_name)["execution_status"]
        for case_name in unresolved
    }
    assert actual == {
        "subject-agent-absent": "EXECUTION_EVIDENCE_PARTIALLY_BOUND",
        "subject-agent-changed": "EXECUTION_EVIDENCE_UNBOUND",
    }
