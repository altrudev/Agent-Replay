from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("agentrust_trace")

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "agentrust_spotlight_demo.py"
SPEC = importlib.util.spec_from_file_location("agentrust_spotlight_demo", SCRIPT)
assert SPEC and SPEC.loader
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


def test_spotlight_record_contains_explicit_transcript_commitment():
    record = demo.base_record(1234567890)

    assert record["iat"] == 1234567890
    assert record["tool_transcript"]["hash"] == demo.synthetic_transcript_hash()
    assert record["tool_transcript"]["call_count"] == len(
        demo.SYNTHETIC_TOOL_TRANSCRIPT
    )
    assert record["tool_transcript"]["hash"].startswith("sha256:")


def test_environment_fingerprint_binds_complete_installed_package_map():
    environment = demo.environment_fingerprint()
    packages = environment["packages"]

    expected = hashlib.sha256(demo.canonical_demo_json(packages)).hexdigest()
    assert environment["packages_sha256"] == expected
    assert packages["agent-replay"] == "0.6.0"
    assert packages["agentrust-trace"] == "0.9.0"


def test_publication_demo_preserves_proof_horizon_and_fails_closed(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    assert demo.main() == 0

    manifest_path = (
        tmp_path / "artifacts" / "agentrust-spotlight" / "spotlight-manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["valid"]["verification"]["status"] == "VERIFIED"
    assert manifest["rejected"]["status"] == "REJECTED"
    assert (
        manifest["adversarial_checks"]["signed_transcript_hash_tamper"]["status"]
        == "REJECTED"
    )
    assert (
        manifest["adversarial_checks"]["wrong_caller_supplied_trusted_key"]["status"]
        == "REJECTED"
    )

    commitment = manifest["transcript_commitment"]
    assert commitment["signed_hash"] == commitment["synthetic_source_hash"]
    assert commitment["source_is_demo_fixture"] is True
    assert commitment["transcript_supplied_to_trace_verifier"] is False
    assert commitment["incident_input_supplied_for_binding_check"] is False
    assert commitment["binding_evaluated"] is False

    boundary = manifest["boundary"]
    assert boundary["transcript_commitment_presence"] == "VERIFIED_AS_SIGNED_FIELD"
    assert boundary["transcript_to_incident_binding"] == "NOT_VERIFIED"
    assert (
        boundary["post_execution_effect"]
        == "NOT_ESTABLISHED_BY_TRACE_VERIFICATION"
    )

    generation = manifest["artifact_generation"]
    assert generation["fresh_key_each_run"] is True
    assert generation["fresh_iat_each_run"] is True
    assert generation["bit_for_bit_reproducible"] is False
