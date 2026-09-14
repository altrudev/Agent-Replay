import json
import sys
import types

import pytest

from agent_replay.trace import TraceEvidenceError, verify_trace_record


def _record():
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1789400000,
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
        "appraisal": {"status": "none", "verifier": "https://verifier.example.test"},
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "embedded"}},
        "signature": "signed",
    }


def test_trace_uses_caller_supplied_key(tmp_path, monkeypatch):
    record_path = tmp_path / "record.json"
    key_path = tmp_path / "issuer.jwk"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    key_path.write_text(
        json.dumps({"kty": "OKP", "crv": "Ed25519", "x": "trusted"}),
        encoding="utf-8",
    )

    calls = {}

    def validate_json(record):
        calls["validated"] = record["subject"]

    def verify_record(record, public_key_or_jwk):
        calls["key"] = public_key_or_jwk
        assert public_key_or_jwk["x"] == "trusted"
        assert public_key_or_jwk != record["cnf"]["jwk"]

    fake = types.SimpleNamespace(
        validate_json=validate_json,
        verify_record=verify_record,
    )
    monkeypatch.setitem(sys.modules, "agentrust_trace", fake)

    summary = verify_trace_record(record_path, key_path)

    assert calls["validated"] == "spiffe://example.test/agent/refund"
    assert summary["verification"]["status"] == "VERIFIED"
    assert summary["verification"]["trusted_key_source"] == "caller-supplied"
    assert summary["subject"] == "spiffe://example.test/agent/refund"
    assert "does not independently verify hardware attestation" in summary["verification"]["scope"]


def test_runtime_claim_is_refused(tmp_path):
    record_path = tmp_path / "claim.json"
    key_path = tmp_path / "issuer.jwk"
    record_path.write_text(
        json.dumps({"trace": _record(), "signature": "outer"}),
        encoding="utf-8",
    )
    key_path.write_text(json.dumps({"kty": "OKP"}), encoding="utf-8")

    with pytest.raises(TraceEvidenceError, match="RuntimeClaim"):
        verify_trace_record(record_path, key_path)
