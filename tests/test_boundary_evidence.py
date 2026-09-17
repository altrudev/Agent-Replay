import base64
import hashlib
import json

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_replay.reconstruct import reconstruct_records


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _signed(private_key, key_id, payload):
    signature = private_key.sign(_canonical(payload))
    return {
        "signature_scheme": "ed25519",
        "key_id": key_id,
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode(),
    }


def _event_digest(event_id, timestamp, actor, kind, observed=None, expected=None, evidence=None, parent_ids=None):
    return hashlib.sha256(_canonical({
        "event_id": event_id,
        "timestamp": timestamp,
        "actor": actor,
        "kind": kind,
        "observed": observed or {},
        "expected": expected or {},
        "evidence": evidence or {},
        "parent_ids": parent_ids or [],
    })).hexdigest()


def _public_b64(private_key):
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def test_authenticated_policy_and_revocation_receipt_are_verified():
    signer = Ed25519PrivateKey.generate()
    boundary = Ed25519PrivateKey.generate()
    expected = {"execution_permitted": False}
    expected_hash = hashlib.sha256(_canonical(expected)).hexdigest()

    policy_payload = {
        "policy_id": "pay-policy",
        "policy_version": "18",
        "authority_version": "18",
        "event_id": "exec-1",
        "subject": "payment",
        "action": "execute",
        "authority_scope": "payment:123",
        "expected_sha256": expected_hash,
        "valid_from": "2026-09-17T20:00:00Z",
        "valid_until": "2026-09-17T22:00:00Z",
    }
    revocation_digest = _event_digest(
        "rev-evt",
        "2026-09-17T20:58:00.000000Z",
        "authority",
        "authority_revoked",
        observed={"authority_version": "18"},
    )
    policy_sha256 = hashlib.sha256(_canonical(policy_payload)).hexdigest()
    receipt_payload = {
        "revocation_id": "rev-1",
        "authority_version": "18",
        "execution_boundary_id": "payment-boundary",
        "received_at": "2026-09-17T20:59:00Z",
        "policy_id": "pay-policy",
        "policy_version": "18",
        "policy_sha256": policy_sha256,
        "revocation_sha256": revocation_digest,
        "revocation_event_id": "rev-evt",
        "nonce": "n-1",
    }
    records = [{
        "event_id": "rev-evt",
        "timestamp": "2026-09-17T20:58:00Z",
        "actor": "authority",
        "kind": "authority_revoked",
        "observed": {"authority_version": "18"},
    }, {
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": expected,
        "observed": {"execution_permitted": True},
        "evidence": {
            "policy_proof": _signed(signer, "policy-key", policy_payload),
            "revocation_receipt": _signed(boundary, "boundary-key", receipt_payload),
        },
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={
            "policy-key": _public_b64(signer),
            "boundary-key": _public_b64(boundary),
        },
    )
    boundary_result = result["boundary_evidence"]
    assert boundary_result["authenticated_expectation_events"] == 1
    assert boundary_result["verified_revocation_receipts"] == 1
    item = boundary_result["events"][0]
    assert item["policy"]["status"] == "VERIFIED"
    assert item["revocation_receipt"]["status"] == "VERIFIED"
    assert result["first_provable_divergence"]["event_id"] == "exec-1"


def test_untrusted_policy_never_becomes_authenticated():
    signer = Ed25519PrivateKey.generate()
    expected = {"execution_permitted": False}
    payload = {
        "policy_id": "pay-policy",
        "policy_version": "18",
        "event_id": "exec-1",
        "expected_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
    }
    records = [{
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": expected,
        "observed": {"execution_permitted": True},
        "evidence": {"policy_proof": _signed(signer, "unknown-key", payload)},
    }]
    result = reconstruct_records(records, input_sha256="0" * 64, trust_store={})
    item = result["boundary_evidence"]["events"][0]
    assert item["policy"]["status"] == "UNTRUSTED_KEY"
    assert result["boundary_evidence"]["authenticated_expectation_events"] == 0


def test_receipt_after_execution_does_not_establish_pre_execution_delivery():
    key = Ed25519PrivateKey.generate()
    revocation_digest = _event_digest(
        "rev-evt",
        "2026-09-17T20:58:00.000000Z",
        "authority",
        "authority_revoked",
        observed={"authority_version": "18"},
    )
    records = [{
        "event_id": "rev-evt",
        "timestamp": "2026-09-17T20:58:00Z",
        "actor": "authority",
        "kind": "authority_revoked",
        "observed": {"authority_version": "18"},
    }, {
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": {"execution_permitted": False},
        "observed": {"execution_permitted": True},
        "evidence": {
            "revocation_receipt": _signed(key, "boundary-key", {
                "revocation_id": "rev-1",
                "authority_version": "18",
                "execution_boundary_id": "payment-boundary",
                "received_at": "2026-09-17T21:01:00Z",
                "policy_id": "pay-policy",
                "policy_version": "18",
                "policy_sha256": "c" * 64,
                "revocation_sha256": revocation_digest,
                "revocation_event_id": "rev-evt",
                "nonce": "n-2",
            })
        },
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={"boundary-key": _public_b64(key)},
    )
    item = result["boundary_evidence"]["events"][0]
    assert item["revocation_receipt"]["status"] == "TEMPORAL_MISMATCH"
    assert result["boundary_evidence"]["verified_revocation_receipts"] == 0


def test_authenticated_policy_without_receipt_keeps_delivery_unresolved():
    signer = Ed25519PrivateKey.generate()
    expected = {"execution_permitted": False}
    policy_payload = {
        "policy_id": "pay-policy",
        "policy_version": "18",
        "authority_version": "18",
        "event_id": "exec-1",
        "subject": "payment",
        "action": "execute",
        "authority_scope": "payment:123",
        "expected_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
    }
    records = [{
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": expected,
        "observed": {"execution_permitted": True},
        "evidence": {"policy_proof": _signed(signer, "policy-key", policy_payload)},
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={"policy-key": _public_b64(signer)},
    )
    item = result["boundary_evidence"]["events"][0]
    assert item["policy"]["status"] == "VERIFIED"
    assert item["revocation_receipt"]["status"] == "NOT_SUPPLIED"
    assert result["boundary_evidence"]["authenticated_expectation_events"] == 1
    assert result["boundary_evidence"]["verified_revocation_receipts"] == 0
    assert result["first_provable_divergence"]["event_id"] == "exec-1"


def test_verified_boundary_with_blocked_execution_has_no_divergence():
    signer = Ed25519PrivateKey.generate()
    boundary = Ed25519PrivateKey.generate()
    expected = {"execution_permitted": False}
    policy_payload = {
        "policy_id": "pay-policy",
        "policy_version": "18",
        "authority_version": "18",
        "event_id": "exec-1",
        "subject": "payment",
        "action": "execute",
        "authority_scope": "payment:123",
        "expected_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
    }
    revocation_digest = _event_digest(
        "rev-evt",
        "2026-09-17T20:58:00.000000Z",
        "authority",
        "authority_revoked",
        observed={"authority_version": "18"},
    )
    receipt_payload = {
        "revocation_id": "rev-1",
        "authority_version": "18",
        "execution_boundary_id": "payment-boundary",
        "received_at": "2026-09-17T20:59:00Z",
        "policy_id": "pay-policy",
        "policy_version": "18",
        "policy_sha256": hashlib.sha256(_canonical(policy_payload)).hexdigest(),
        "revocation_sha256": revocation_digest,
        "revocation_event_id": "rev-evt",
        "nonce": "n-block",
    }
    records = [{
        "event_id": "rev-evt",
        "timestamp": "2026-09-17T20:58:00Z",
        "actor": "authority",
        "kind": "authority_revoked",
        "observed": {"authority_version": "18"},
    }, {
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": expected,
        "observed": {"execution_permitted": False},
        "evidence": {
            "policy_proof": _signed(signer, "policy-key", policy_payload),
            "revocation_receipt": _signed(boundary, "boundary-key", receipt_payload),
        },
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={
            "policy-key": _public_b64(signer),
            "boundary-key": _public_b64(boundary),
        },
    )
    assert result["first_provable_divergence"] is None
    assert result["boundary_evidence"]["authenticated_expectation_events"] == 1
    assert result["boundary_evidence"]["verified_revocation_receipts"] == 1


def test_signed_payload_with_float_fails_closed():
    signer = Ed25519PrivateKey.generate()
    expected = {"execution_permitted": False}
    payload = {
        "policy_id": "pay-policy",
        "policy_version": "18",
        "authority_version": "18",
        "event_id": "exec-1",
        "subject": "payment",
        "action": "execute",
        "authority_scope": {"amount": 750.0},
        "expected_sha256": hashlib.sha256(_canonical(expected)).hexdigest(),
    }
    records = [{
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": expected,
        "observed": {"execution_permitted": True},
        "evidence": {"policy_proof": _signed(signer, "policy-key", payload)},
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={"policy-key": _public_b64(signer)},
    )
    assert result["boundary_evidence"]["events"][0]["policy"]["status"] == "INVALID_REPRESENTATION"


def test_same_receipt_can_be_reused_but_nonce_payload_collision_is_rejected():
    boundary = Ed25519PrivateKey.generate()
    revocation_digest = _event_digest(
        "rev-evt",
        "2026-09-17T20:58:00.000000Z",
        "authority",
        "authority_revoked",
        observed={"authority_version": "18"},
    )
    base = {
        "revocation_id": "rev-1",
        "authority_version": "18",
        "execution_boundary_id": "payment-boundary",
        "received_at": "2026-09-17T20:59:00Z",
        "policy_id": "pay-policy",
        "policy_version": "18",
        "policy_sha256": "c" * 64,
        "revocation_sha256": revocation_digest,
        "revocation_event_id": "rev-evt",
        "nonce": "same-nonce",
    }
    first_receipt = _signed(boundary, "boundary-key", base)
    altered = dict(base)
    altered["revocation_id"] = "rev-2"
    second_receipt = _signed(boundary, "boundary-key", altered)
    records = [{
        "event_id": "rev-evt",
        "timestamp": "2026-09-17T20:58:00Z",
        "actor": "authority",
        "kind": "authority_revoked",
        "observed": {"authority_version": "18"},
    }, {
        "event_id": "exec-1",
        "timestamp": "2026-09-17T21:00:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": {"execution_permitted": False},
        "observed": {"execution_permitted": True},
        "evidence": {"revocation_receipt": first_receipt},
    }, {
        "event_id": "exec-2",
        "timestamp": "2026-09-17T21:01:00Z",
        "actor": "executor",
        "kind": "execution_decision",
        "expected": {"execution_permitted": False},
        "observed": {"execution_permitted": True},
        "evidence": {"revocation_receipt": second_receipt},
    }]
    result = reconstruct_records(
        records,
        input_sha256="0" * 64,
        trust_store={"boundary-key": _public_b64(boundary)},
    )
    items = result["boundary_evidence"]["events"]
    assert items[0]["revocation_receipt"]["status"] == "VERIFIED"
    assert items[1]["revocation_receipt"]["status"] == "NONCE_COLLISION"
    assert result["boundary_evidence"]["verified_revocation_receipts"] == 1
