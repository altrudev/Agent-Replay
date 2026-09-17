from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .model import CanonicalEvent


class BoundaryProofError(ValueError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def load_trust_store(path: str | Path | None) -> dict[str, str]:
    if path is None:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and k and isinstance(v, str) and v for k, v in raw.items()
    ):
        raise BoundaryProofError("trust store must be a JSON object of key_id -> base64 Ed25519 public key")
    return dict(raw)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _verify_ed25519(
    payload: dict[str, Any],
    *,
    signature_b64: Any,
    key_id: Any,
    trust_store: Mapping[str, str],
) -> tuple[str, str]:
    if not isinstance(key_id, str) or not key_id:
        return "INVALID_PROOF", "missing key_id"
    trusted_key = trust_store.get(key_id)
    if trusted_key is None:
        return "UNTRUSTED_KEY", "key_id is not present in caller-supplied trust store"
    if not isinstance(signature_b64, str) or not signature_b64:
        return "INVALID_PROOF", "missing signature_b64"
    try:
        public_key_bytes = base64.b64decode(trusted_key, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return "INVALID_PROOF", "invalid base64 key or signature"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "VERIFIER_UNAVAILABLE", "install agent-replay[proof] to verify Ed25519 proofs"
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature, _canonical_bytes(payload)
        )
    except Exception:
        return "SIGNATURE_INVALID", "Ed25519 signature verification failed"
    return "VERIFIED", "signature verified against caller-supplied trusted key"


def _verify_envelope(
    envelope: Any,
    *,
    trust_store: Mapping[str, str],
) -> tuple[str, str, dict[str, Any] | None]:
    if not isinstance(envelope, dict):
        return "NOT_SUPPLIED", "proof envelope not supplied", None
    if envelope.get("signature_scheme") != "ed25519":
        return "UNSUPPORTED_SCHEME", "only ed25519 is supported", None
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return "INVALID_PROOF", "payload must be an object", None
    status, basis = _verify_ed25519(
        payload,
        signature_b64=envelope.get("signature_b64"),
        key_id=envelope.get("key_id"),
        trust_store=trust_store,
    )
    return status, basis, payload


def _policy_assessment(
    event: CanonicalEvent,
    *,
    trust_store: Mapping[str, str],
) -> dict[str, Any]:
    status, basis, payload = _verify_envelope(
        event.evidence.get("policy_proof"),
        trust_store=trust_store,
    )
    result: dict[str, Any] = {"status": status, "basis": basis}
    if payload is None:
        return result

    result["key_id"] = event.evidence.get("policy_proof", {}).get("key_id")
    result["policy_id"] = payload.get("policy_id")
    result["policy_version"] = payload.get("policy_version")

    expected_sha256 = sha256_json(event.expected)
    result["expected_sha256"] = expected_sha256
    if status == "VERIFIED":
        if payload.get("event_id") != event.event_id:
            result.update(status="BINDING_MISMATCH", basis="signed policy proof is bound to a different event_id")
        elif payload.get("expected_sha256") != expected_sha256:
            result.update(status="BINDING_MISMATCH", basis="signed policy proof does not bind this event's expected state")
        else:
            event_time = _parse_time(event.timestamp)
            valid_from = _parse_time(payload.get("valid_from"))
            valid_until = _parse_time(payload.get("valid_until"))
            if payload.get("valid_from") is not None and valid_from is None:
                result.update(status="INVALID_PROOF", basis="valid_from is not a timezone-aware ISO-8601 timestamp")
            elif payload.get("valid_until") is not None and valid_until is None:
                result.update(status="INVALID_PROOF", basis="valid_until is not a timezone-aware ISO-8601 timestamp")
            elif event_time and valid_from and event_time < valid_from:
                result.update(status="POLICY_NOT_YET_VALID", basis="event predates signed policy validity")
            elif event_time and valid_until and event_time > valid_until:
                result.update(status="POLICY_EXPIRED", basis="event occurs after signed policy validity")
            else:
                result["basis"] = "signed policy proof verified and bound to this event and expected state"
    return result


def _receipt_assessment(
    event: CanonicalEvent,
    *,
    trust_store: Mapping[str, str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    status, basis, payload = _verify_envelope(
        event.evidence.get("revocation_receipt"),
        trust_store=trust_store,
    )
    result: dict[str, Any] = {"status": status, "basis": basis}
    if payload is None:
        return result

    result["key_id"] = event.evidence.get("revocation_receipt", {}).get("key_id")
    for field in (
        "revocation_id",
        "authority_version",
        "execution_boundary_id",
        "received_at",
        "policy_id",
        "policy_version",
        "revocation_sha256",
        "nonce",
    ):
        if field in payload:
            result[field] = payload[field]

    if status == "VERIFIED":
        received_at = _parse_time(payload.get("received_at"))
        event_time = _parse_time(event.timestamp)
        if received_at is None:
            result.update(status="INVALID_PROOF", basis="received_at is missing or invalid")
        elif event_time and received_at > event_time:
            result.update(status="TEMPORAL_MISMATCH", basis="receipt claims delivery after the execution event")
        elif policy.get("status") == "VERIFIED" and (
            payload.get("policy_id") != policy.get("policy_id")
            or payload.get("policy_version") != policy.get("policy_version")
        ):
            result.update(status="BINDING_MISMATCH", basis="receipt is bound to a different policy identity/version")
        else:
            result["basis"] = "signed receipt verified and establishes delivery no later than this execution event"
    return result


def assess_boundary_evidence(
    events: list[CanonicalEvent],
    *,
    trust_store: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    trusted = trust_store or {}
    assessments: list[dict[str, Any]] = []
    authenticated_expectations = 0
    verified_receipts = 0

    for event in events:
        policy = _policy_assessment(event, trust_store=trusted)
        receipt = _receipt_assessment(event, trust_store=trusted, policy=policy)
        if policy["status"] == "VERIFIED":
            authenticated_expectations += 1
        if receipt["status"] == "VERIFIED":
            verified_receipts += 1
        if policy["status"] != "NOT_SUPPLIED" or receipt["status"] != "NOT_SUPPLIED":
            assessments.append(
                {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "policy": policy,
                    "revocation_receipt": receipt,
                }
            )

    return {
        "schema": "agent-replay.boundary-evidence.v1",
        "trust_store_configured": bool(trusted),
        "authenticated_expectation_events": authenticated_expectations,
        "verified_revocation_receipts": verified_receipts,
        "events": assessments,
        "claim_scope": (
            "Cryptographic verification establishes integrity and binding to caller-trusted "
            "Ed25519 keys. Agent Replay does not decide whether a trusted signer was entitled "
            "to define policy or revoke authority beyond the supplied trust configuration."
        ),
    }
