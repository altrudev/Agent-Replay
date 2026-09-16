import json
import time

import pytest

agentrust_trace = pytest.importorskip("agentrust_trace")
from cryptography.exceptions import InvalidSignature

from agent_replay.trace import verify_trace_record


def _base_record() -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "spiffe://example.test/agent/refund",
        "model": {"provider": "example", "model_id": "demo"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "b" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 1,
            "digest": "sha256:" + "e" * 64,
        },
        "appraisal": {
            "status": "none",
            "verifier": "https://verifier.example.test",
        },
        "transparency": "https://registry.example.test/trace/sample",
    }


def _write_case(tmp_path):
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(_base_record(), key)
    record_path = tmp_path / "record.json"
    key_path = tmp_path / "issuer.jwk"
    record_path.write_text(json.dumps(signed), encoding="utf-8")
    key_path.write_text(json.dumps(agentrust_trace.key_to_jwk(key)), encoding="utf-8")
    return signed, record_path, key_path


def test_real_trace_verifier_accepts_valid_signed_record(tmp_path):
    _, record_path, key_path = _write_case(tmp_path)

    summary = verify_trace_record(record_path, key_path)

    assert summary["verification"]["status"] == "VERIFIED"
    assert summary["verification"]["trusted_key_source"] == "caller-supplied"
    assert summary["verifier_package"] == {
        "name": "agentrust-trace",
        "version": "0.9.0",
    }


def test_real_trace_verifier_rejects_tampering(tmp_path):
    signed, record_path, key_path = _write_case(tmp_path)
    signed["subject"] = "spiffe://example.test/agent/tampered"
    record_path.write_text(json.dumps(signed), encoding="utf-8")

    with pytest.raises(InvalidSignature):
        verify_trace_record(record_path, key_path)


def test_real_trace_verifier_rejects_wrong_trusted_key(tmp_path):
    _, record_path, _ = _write_case(tmp_path)
    wrong_key = agentrust_trace.generate_key()
    wrong_key_path = tmp_path / "wrong.jwk"
    wrong_key_path.write_text(
        json.dumps(agentrust_trace.key_to_jwk(wrong_key)),
        encoding="utf-8",
    )

    with pytest.raises(InvalidSignature):
        verify_trace_record(record_path, wrong_key_path)
