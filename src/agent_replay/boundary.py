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


def _event_digest(event: CanonicalEvent) -> str:
    return sha256_json({
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "actor": event.actor,
        "kind": event.kind,
        "observed": event.observed,
        "expected": event.expected,
        "evidence": event.evidence,
        "parent_ids": list(event.parent_ids),
    })


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [name for name in required if payload.get(name) in (None, "")]


def _validate_signed_value(value: Any, path: str = "$") -> str | None:
    if value is None or isinstance(value, (str, bool, int)):
        return None
    if isinstance(value, float):
        return f"{path}: floating-point values are not permitted in signed payloads"
    if isinstance(value, list):
        for index, item in enumerate(value):
            error = _validate_signed_value(item, f"{path}[{index}]")
            if error:
                return error
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return f"{path}: object keys must be strings"
            error = _validate_signed_value(item, f"{path}.{key}")
            if error:
                return error
        return None
    return f"{path}: unsupported signed value type {type(value).__name__}"


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
    representation_error = _validate_signed_value(payload)
    if representation_error:
        return "INVALID_REPRESENTATION", representation_error, payload
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
    result["policy_sha256"] = sha256_json(payload)
    result["authority_version"] = payload.get("authority_version")

    expected_sha256 = sha256_json(event.expected)
    result["expected_sha256"] = expected_sha256
    if status == "VERIFIED":
        missing = _missing_fields(payload, (
            "policy_id", "policy_version", "authority_version", "event_id",
            "subject", "action", "authority_scope", "expected_sha256",
        ))
        if missing:
            result.update(status="INVALID_PROOF", basis="signed policy proof missing required fields: " + ", ".join(missing))
        elif payload.get("event_id") != event.event_id:
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
    events_by_id: Mapping[str, CanonicalEvent],
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
        "policy_sha256",
        "revocation_sha256",
        "revocation_event_id",
        "nonce",
    ):
        if field in payload:
            result[field] = payload[field]

    if status == "VERIFIED":
        missing = _missing_fields(payload, (
            "revocation_id", "authority_version", "execution_boundary_id",
            "received_at", "policy_id", "policy_version", "policy_sha256",
            "revocation_sha256", "revocation_event_id", "nonce",
        ))
        received_at = _parse_time(payload.get("received_at"))
        event_time = _parse_time(event.timestamp)
        revocation_event = events_by_id.get(str(payload.get("revocation_event_id", "")))
        if missing:
            result.update(status="INVALID_PROOF", basis="signed revocation receipt missing required fields: " + ", ".join(missing))
        elif received_at is None:
            result.update(status="INVALID_PROOF", basis="received_at is missing or invalid")
        elif event_time and received_at > event_time:
            result.update(status="TEMPORAL_MISMATCH", basis="receipt claims delivery after the execution event")
        elif revocation_event is None:
            result.update(status="MISSING_BOUND_EVIDENCE", basis="receipt references a revocation event not present in supplied evidence")
        elif payload.get("revocation_sha256") != _event_digest(revocation_event):
            result.update(status="BINDING_MISMATCH", basis="receipt does not bind the supplied revocation event bytes")
        elif payload.get("authority_version") != revocation_event.observed.get("authority_version"):
            result.update(status="BINDING_MISMATCH", basis="receipt authority_version does not match the bound revocation event")
        elif received_at < (_parse_time(revocation_event.timestamp) or received_at):
            result.update(status="TEMPORAL_MISMATCH", basis="receipt claims delivery before the bound revocation event")
        elif policy.get("status") == "VERIFIED" and (
            payload.get("policy_id") != policy.get("policy_id")
            or payload.get("policy_version") != policy.get("policy_version")
            or payload.get("policy_sha256") != policy.get("policy_sha256")
            or payload.get("authority_version") != policy.get("authority_version")
        ):
            result.update(status="BINDING_MISMATCH", basis="receipt is bound to a different policy or authority version")
        else:
            result["revocation_authority_state"] = (
                revocation_event.observed.get("authority_status")
                if "authority_status" in revocation_event.observed
                else revocation_event.observed.get("authority_state")
            )
            result["revocation_authority_version"] = revocation_event.observed.get("authority_version")
            result["basis"] = "signed receipt verified and establishes delivery no later than this execution event"
    return result


def _evaluation_assessment(
    event: CanonicalEvent,
    *,
    trust_store: Mapping[str, str],
    policy: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    status, basis, payload = _verify_envelope(
        event.evidence.get("execution_evaluation"),
        trust_store=trust_store,
    )
    result: dict[str, Any] = {"status": status, "basis": basis}
    if payload is None:
        return result

    result["key_id"] = event.evidence.get("execution_evaluation", {}).get("key_id")
    for field in (
        "evaluation_id",
        "event_id",
        "execution_boundary_id",
        "evaluated_at",
        "decision_at",
        "authority_state",
        "authority_version",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "revocation_receipt_sha256",
        "observed_sha256",
    ):
        if field in payload:
            result[field] = payload[field]

    if status == "VERIFIED":
        missing = _missing_fields(payload, (
            "evaluation_id", "event_id", "execution_boundary_id",
            "evaluated_at", "decision_at", "authority_state", "authority_version",
            "policy_id", "policy_version", "policy_sha256",
            "revocation_receipt_sha256", "observed_sha256",
        ))
        evaluated_at = _parse_time(payload.get("evaluated_at"))
        decision_at = _parse_time(payload.get("decision_at"))
        event_time = _parse_time(event.timestamp)
        receipt_payload = event.evidence.get("revocation_receipt", {}).get("payload", {})
        receipt_digest = sha256_json(receipt_payload) if isinstance(receipt_payload, dict) else None
        receipt_time = _parse_time(receipt.get("received_at"))
        observed_sha256 = sha256_json(event.observed)

        if missing:
            result.update(
                status="INVALID_PROOF",
                basis="signed execution evaluation missing required fields: " + ", ".join(missing),
            )
        elif payload.get("event_id") != event.event_id:
            result.update(
                status="BINDING_MISMATCH",
                basis="signed execution evaluation is bound to a different event_id",
            )
        elif evaluated_at is None or decision_at is None:
            result.update(
                status="INVALID_PROOF",
                basis="evaluated_at or decision_at is missing or invalid",
            )
        elif evaluated_at > decision_at:
            result.update(
                status="TEMPORAL_MISMATCH",
                basis="evaluation claims to occur after the signed execution decision",
            )
        elif event_time and decision_at != event_time:
            result.update(
                status="BINDING_MISMATCH",
                basis="signed execution decision time does not match the reconstructed execution event time",
            )
        elif receipt.get("status") != "VERIFIED":
            result.update(
                status="UNVERIFIED_INPUT",
                basis="execution evaluation references revocation delivery that is not independently verified",
            )
        elif receipt_time and evaluated_at < receipt_time:
            result.update(
                status="TEMPORAL_MISMATCH",
                basis="execution evaluation predates verified revocation delivery",
            )
        elif payload.get("revocation_receipt_sha256") != receipt_digest:
            result.update(
                status="BINDING_MISMATCH",
                basis="execution evaluation does not bind the verified revocation receipt",
            )
        elif payload.get("execution_boundary_id") != receipt.get("execution_boundary_id"):
            result.update(
                status="BINDING_MISMATCH",
                basis="execution evaluation and revocation receipt name different execution boundaries",
            )
        elif result.get("key_id") != receipt.get("key_id"):
            result.update(
                status="IDENTITY_MISMATCH",
                basis="execution evaluation and delivery receipt were not signed by the same trusted boundary key",
            )
        elif (
            receipt.get("revocation_authority_state") is not None
            and payload.get("authority_state") != receipt.get("revocation_authority_state")
        ):
            result.update(
                status="STATE_MISMATCH",
                basis="execution evaluation did not evaluate the authority state established by the bound revocation event",
            )
        elif payload.get("authority_version") != receipt.get("revocation_authority_version"):
            result.update(
                status="STATE_MISMATCH",
                basis="execution evaluation did not evaluate the authority version established by the bound revocation event",
            )
        elif payload.get("observed_sha256") != observed_sha256:
            result.update(
                status="BINDING_MISMATCH",
                basis="execution evaluation does not bind this event's observed decision state",
            )
        elif policy.get("status") == "VERIFIED" and (
            payload.get("policy_id") != policy.get("policy_id")
            or payload.get("policy_version") != policy.get("policy_version")
            or payload.get("policy_sha256") != policy.get("policy_sha256")
            or payload.get("authority_version") != policy.get("authority_version")
        ):
            result.update(
                status="BINDING_MISMATCH",
                basis="execution evaluation is bound to a different policy or authority version",
            )
        elif (
            payload.get("policy_id") != receipt.get("policy_id")
            or payload.get("policy_version") != receipt.get("policy_version")
            or payload.get("policy_sha256") != receipt.get("policy_sha256")
            or payload.get("authority_version") != receipt.get("authority_version")
        ):
            result.update(
                status="BINDING_MISMATCH",
                basis="execution evaluation is inconsistent with the verified revocation receipt",
            )
        else:
            result["basis"] = (
                "signed execution evaluation verified, occurred after verified revocation delivery, "
                "and is bound to this event's observed decision state"
            )
    return result


def _enforcement_assessment(
    event: CanonicalEvent,
    *,
    policy: dict[str, Any],
    receipt: dict[str, Any],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    if receipt.get("status") != "VERIFIED":
        return {
            "status": "DELIVERY_UNVERIFIED",
            "basis": "revocation delivery to the execution boundary is not independently verified",
        }
    if evaluation.get("status") != "VERIFIED":
        return {
            "status": "DELIVERY_VERIFIED_EVALUATION_UNRESOLVED",
            "basis": (
                "revocation delivery is verified, but no verified execution-time evaluation "
                "establishes that the boundary used the received state"
            ),
        }
    if policy.get("status") != "VERIFIED":
        return {
            "status": "EVALUATION_VERIFIED_EXPECTATION_UNAUTHENTICATED",
            "basis": (
                "execution-time evaluation is verified, but the expected behavior is not "
                "independently authenticated"
            ),
        }

    expected = event.expected
    observed = event.observed
    expectation_matches = all(observed.get(field) == value for field, value in expected.items())
    if expectation_matches:
        return {
            "status": "ENFORCEMENT_CONSISTENT",
            "basis": (
                "verified delivery and execution-time evaluation are bound to an observed "
                "decision consistent with the authenticated expected state"
            ),
        }
    return {
        "status": "ENFORCEMENT_DIVERGED",
        "basis": (
            "verified delivery and execution-time evaluation are bound to an observed "
            "decision that diverges from the authenticated expected state"
        ),
    }


def assess_boundary_evidence(
    events: list[CanonicalEvent],
    *,
    trust_store: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    trusted = trust_store or {}
    assessments: list[dict[str, Any]] = []
    authenticated_expectations = 0
    verified_receipts = 0
    verified_evaluations = 0
    enforcement_consistent = 0
    enforcement_diverged = 0
    events_by_id = {event.event_id: event for event in events}
    seen_receipt_nonces: dict[tuple[str, str], str] = {}
    verified_receipt_digests: set[str] = set()

    for event in events:
        policy = _policy_assessment(event, trust_store=trusted)
        receipt = _receipt_assessment(
            event,
            trust_store=trusted,
            policy=policy,
            events_by_id=events_by_id,
        )
        evaluation = _evaluation_assessment(
            event,
            trust_store=trusted,
            policy=policy,
            receipt=receipt,
        )
        enforcement = _enforcement_assessment(
            event,
            policy=policy,
            receipt=receipt,
            evaluation=evaluation,
        )

        if receipt["status"] == "VERIFIED":
            nonce_key = (str(receipt.get("key_id", "")), str(receipt.get("nonce", "")))
            receipt_digest = sha256_json(
                event.evidence.get("revocation_receipt", {}).get("payload", {})
            )
            prior_digest = seen_receipt_nonces.get(nonce_key)
            if prior_digest is not None and prior_digest != receipt_digest:
                receipt.update(
                    status="NONCE_COLLISION",
                    basis="the same key_id and receipt nonce were observed with different signed payloads",
                )
            else:
                if prior_digest == receipt_digest:
                    receipt["reused_receipt"] = True
                seen_receipt_nonces[nonce_key] = receipt_digest
        if policy["status"] == "VERIFIED":
            authenticated_expectations += 1
        if evaluation["status"] == "VERIFIED":
            verified_evaluations += 1
        if enforcement["status"] == "ENFORCEMENT_CONSISTENT":
            enforcement_consistent += 1
        elif enforcement["status"] == "ENFORCEMENT_DIVERGED":
            enforcement_diverged += 1
        if receipt["status"] == "VERIFIED":
            receipt_digest = sha256_json(
                event.evidence.get("revocation_receipt", {}).get("payload", {})
            )
            if receipt_digest not in verified_receipt_digests:
                verified_receipt_digests.add(receipt_digest)
                verified_receipts += 1
        if (
            policy["status"] != "NOT_SUPPLIED"
            or receipt["status"] != "NOT_SUPPLIED"
            or evaluation["status"] != "NOT_SUPPLIED"
        ):
            assessments.append(
                {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "policy": policy,
                    "revocation_receipt": receipt,
                    "execution_evaluation": evaluation,
                    "enforcement": enforcement,
                }
            )

    return {
        "schema": "agent-replay.boundary-evidence.v1",
        "trust_store_configured": bool(trusted),
        "authenticated_expectation_events": authenticated_expectations,
        "verified_revocation_receipts": verified_receipts,
        "verified_execution_evaluations": verified_evaluations,
        "enforcement_consistent_events": enforcement_consistent,
        "enforcement_diverged_events": enforcement_diverged,
        "events": assessments,
        "replay_scope": "INCIDENT_LOCAL_ONLY",
        "canonicalization": (
            "AGENT_REPLAY_JSON_V1: UTF-8 JSON, sorted object keys, compact separators, "
            "no Unicode normalization, and no floating-point values in signed payloads."
        ),
        "claim_scope": (
            "Cryptographic verification establishes integrity and binding to caller-trusted "
            "Ed25519 keys. Agent Replay does not decide whether a trusted signer was entitled "
            "to define policy or revoke authority beyond the supplied trust configuration. "
            "A verified receipt proves delivery to the signed execution_boundary_id. A verified "
            "execution evaluation separately proves that the same named boundary evaluated after "
            "that delivery and bound the evaluation to the observed decision state. Enforcement "
            "consistency is assessed only when policy, delivery, and evaluation are all verified. "
            "Linking these signed identities to the same real-world component still depends on "
            "the caller's trust configuration and supplied identity evidence. Within one incident, "
            "reusing the same verified receipt is allowed, while the same key_id and nonce "
            "with different signed payloads is rejected as a nonce collision. Cross-incident "
            "replay prevention belongs to the issuing boundary or a persistent verifier."
        ),
    }
