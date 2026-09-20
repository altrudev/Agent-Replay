from __future__ import annotations

from typing import Any


APS_FIXTURE_REPOSITORY = "Agent-Authority-Conformance/aps-conformance-suite"
APS_FIXTURE_REVISION = "6e8b05b202d727ef18e84e100fc31db11f36529f"
APS_FIXTURE_FAMILY = "fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1"


def _first_signature(receipt: dict[str, Any]) -> dict[str, Any]:
    signatures = receipt.get("signatures")
    if isinstance(signatures, list) and signatures and isinstance(signatures[0], dict):
        return signatures[0]
    return {}


def _delegation_path(delegations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "delegation_id": item.get("delegation_id"),
            "parent_delegation_id": item.get("parent_delegation_id"),
            "issuer": item.get("issuer"),
            "subject": item.get("subject"),
            "not_before": (item.get("authority") or {}).get("time", {}).get("not_before"),
            "not_after": (item.get("authority") or {}).get("time", {}).get("not_after"),
        }
        for item in delegations
        if isinstance(item, dict)
    ]


def _external_authority_status(document: dict[str, Any], decision: dict[str, Any]) -> str:
    reasons = set(document.get("expectReasons") or [])
    if "AUTH_DELEGATION_REVOKED" in reasons:
        return "SUPPLIED_REVOKED"
    if "AUTH_DELEGATION_EXPIRED" in reasons:
        return "SUPPLIED_EXPIRED"
    if "SIGNATURE_INVALID" in reasons and "HALT_AUTHORITY" in reasons:
        return "SUPPLIED_SIGNATURE_INVALID"
    if "POLICY_DENIED" in reasons or (decision.get("result") or {}).get("verdict") == "deny":
        return "SUPPLIED_DENIED"
    if document.get("expected") == "allowed":
        return "SUPPLIED_ALLOWED"
    if "HALT_AUTHORITY" in reasons:
        return "SUPPLIED_INVALID"
    return "NOT_ESTABLISHED"


def _receipt_authentication_status(
    document: dict[str, Any],
    receipt: dict[str, Any],
    *,
    receipt_role: str,
) -> str:
    sig = _first_signature(receipt)
    signer = sig.get("signer")
    issuer = receipt.get("issuer")
    if not signer or not issuer:
        return "MISSING"

    reasons = set(document.get("expectReasons") or [])
    sub_results = set(document.get("expected_sub_results") or [])
    if receipt_role == "decision" and (
        "decision_signature_invalid" in sub_results
        or ("SIGNATURE_INVALID" in reasons and "HALT_AUTHORITY" in reasons)
    ):
        return "FAILED_BY_SUPPLIED_CONFORMANCE"
    if signer != issuer:
        return "CLAIMED_SIGNER_MISMATCH"
    return "CLAIMED_SIGNER_CONSISTENT"


def _binding(
    intent: dict[str, Any],
    decision: dict[str, Any],
    path: list[dict[str, Any]],
) -> dict[str, Any]:
    intent_action_ref = intent.get("action_ref")
    decision_action_ref = decision.get("action_ref")
    intent_receipt_id = intent.get("receipt_id")
    decision_prev = decision.get("prev")
    intent_delegation_ref = intent.get("delegation_ref")
    decision_delegation_ref = decision.get("delegation_ref")
    leaf_delegation_id = path[-1].get("delegation_id") if path else None

    action_ref = bool(intent_action_ref) and intent_action_ref == decision_action_ref
    receipt_link = bool(intent_receipt_id) and decision_prev == intent_receipt_id
    delegation_ref = (
        bool(intent_delegation_ref)
        and intent_delegation_ref == decision_delegation_ref
        and intent_delegation_ref == leaf_delegation_id
    )

    chain_continuity = bool(path)
    if path:
        if path[0].get("parent_delegation_id") not in (None, ""):
            chain_continuity = False
        for previous, current in zip(path, path[1:]):
            if current.get("parent_delegation_id") != previous.get("delegation_id"):
                chain_continuity = False

    checks = {
        "action_ref": action_ref,
        "receipt_link": receipt_link,
        "delegation_ref": delegation_ref,
        "delegation_chain": chain_continuity,
    }
    if all(checks.values()):
        status = "COMPLETE"
    elif any(checks.values()):
        status = "PARTIAL"
    else:
        status = "BROKEN"

    return {
        "status": status,
        "checks": checks,
        "intent_action_ref": intent_action_ref,
        "decision_action_ref": decision_action_ref,
        "intent_receipt_id": intent_receipt_id,
        "decision_prev": decision_prev,
        "intent_delegation_ref": intent_delegation_ref,
        "decision_delegation_ref": decision_delegation_ref,
        "leaf_delegation_id": leaf_delegation_id,
    }


def _action_result_receipts(
    document: dict[str, Any],
    envelope: dict[str, Any],
) -> tuple[list[dict[str, Any]], int]:
    raw = envelope.get("action_results")
    if raw is None:
        single = envelope.get("action_result")
        if single is not None:
            raw = [single]
    if raw is None:
        raw = document.get("action_results")
    if raw is None:
        single = document.get("action_result")
        if single is not None:
            raw = [single]

    if raw is None:
        return [], 0
    if not isinstance(raw, list):
        return [], 1

    receipts = [item for item in raw if isinstance(item, dict)]
    return receipts, len(raw) - len(receipts)


def _normalize_action_result(
    receipt: dict[str, Any],
    *,
    decision: dict[str, Any],
) -> dict[str, Any]:
    result = receipt.get("result")
    if not isinstance(result, dict):
        result = {}

    decision_receipt_id = decision.get("receipt_id")
    decision_ref = decision.get("decision_ref")
    supplied_decision_ref = receipt.get("decision_ref")
    prev = receipt.get("prev")
    return {
        "evidence_kind": "APS_ACTION_RESULT",
        "artifact_type": (
            receipt.get("artifact_type")
            or receipt.get("receipt_type")
            or receipt.get("type")
            or "aps:action-result:v1"
        ),
        "receipt_id": receipt.get("receipt_id"),
        "issuer": receipt.get("issuer"),
        "actor": receipt.get("subject_agent") or receipt.get("actor"),
        "action_ref": receipt.get("action_ref"),
        "decision_ref": supplied_decision_ref,
        "prev": prev,
        "status": result.get("status") or receipt.get("status"),
        "effect_ref": result.get("effect_ref") or receipt.get("effect_ref"),
        "error_code": result.get("error_code") or receipt.get("error_code"),
        "decision_receipt_id": decision_receipt_id,
        "decision_ref_matches_decision": (
            bool(decision_ref) and supplied_decision_ref == decision_ref
        ),
        "prev_matches_decision_receipt": (
            bool(decision_receipt_id) and prev == decision_receipt_id
        ),
        "external_effect_proof": False,
        "observation_scope": "ENFORCEMENT_BOUNDARY_POST_DISPATCH",
    }


def _execution_evidence(
    document: dict[str, Any],
    envelope: dict[str, Any],
    *,
    action_ref: Any,
    claimed_actor: Any,
    decision: dict[str, Any],
) -> dict[str, Any]:
    raw = envelope.get("execution_events")
    if raw is None:
        raw = document.get("execution_events")
    if isinstance(raw, list):
        generic_events = [item for item in raw if isinstance(item, dict)]
        malformed_count = len(raw) - len(generic_events)
    elif raw is None:
        generic_events = []
        malformed_count = 0
    else:
        generic_events = []
        malformed_count = 1

    action_results, malformed_action_results = _action_result_receipts(document, envelope)
    malformed_count += malformed_action_results

    events: list[dict[str, Any]] = []
    for event in generic_events:
        normalized = dict(event)
        normalized.setdefault("evidence_kind", "EXECUTION_EVENT")
        normalized.setdefault("external_effect_proof", False)
        events.append(normalized)
    events.extend(
        _normalize_action_result(receipt, decision=decision)
        for receipt in action_results
    )

    if not events and malformed_count == 0:
        return {
            "status": "NO_EXECUTION_EVIDENCE",
            "events": [],
            "bound_events": [],
            "partially_bound_events": [],
            "unbound_events": [],
            "malformed_event_count": 0,
            "independent_authentication": "NOT_VERIFIED",
            "external_effect_proof": False,
        }

    bound: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []

    for event in events:
        event_action_ref = event.get("action_ref")
        event_actor = event.get("actor")
        action_match = bool(action_ref) and event_action_ref == action_ref
        actor_present = event_actor not in (None, "")
        actor_match = actor_present and event_actor == claimed_actor
        evidence_kind = event.get("evidence_kind")

        if evidence_kind == "APS_ACTION_RESULT":
            receipt_link = event.get("prev_matches_decision_receipt") is True
            decision_ref_match = event.get("decision_ref_matches_decision") is True
            if action_match and actor_match and receipt_link and decision_ref_match:
                bound.append(event)
            elif action_match and (actor_match or not actor_present):
                partial.append(event)
            else:
                unbound.append(event)
            continue

        if action_match and actor_match:
            bound.append(event)
        elif action_match and not actor_present:
            partial.append(event)
        else:
            unbound.append(event)

    if bound and not partial and not unbound and malformed_count == 0:
        status = "EXECUTION_EVIDENCE_BOUND_TO_ACTION"
    elif bound or partial:
        status = "EXECUTION_EVIDENCE_PARTIALLY_BOUND"
    else:
        status = "EXECUTION_EVIDENCE_UNBOUND"

    return {
        "status": status,
        "events": events,
        "bound_events": bound,
        "partially_bound_events": partial,
        "unbound_events": unbound,
        "malformed_event_count": malformed_count,
        "independent_authentication": "NOT_VERIFIED",
        "external_effect_proof": False,
    }


def reconstruct_aps_fixture(
    document: dict[str, Any],
    *,
    input_sha256: str | None = None,
) -> dict[str, Any]:
    """Reconstruct APS authority evidence without promoting unsupported claims."""
    envelope = document.get("envelope")
    if not isinstance(envelope, dict):
        raise ValueError("APS fixture must contain an envelope object")

    intent = envelope.get("intent") or {}
    decision = envelope.get("decision") or {}
    delegations = envelope.get("delegations") or []
    if not isinstance(intent, dict) or not isinstance(decision, dict):
        raise ValueError("APS envelope intent and decision must be objects")
    if not isinstance(delegations, list):
        raise ValueError("APS envelope delegations must be a list")
    if not all(isinstance(item, dict) for item in delegations):
        raise ValueError("APS envelope delegations must contain only objects")

    path = _delegation_path(delegations)
    claimed_actor = intent.get("subject_agent") or intent.get("issuer")
    binding = _binding(intent, decision, path)
    execution = _execution_evidence(
        document,
        envelope,
        action_ref=intent.get("action_ref"),
        claimed_actor=claimed_actor,
        decision=decision,
    )
    intent_sig = _first_signature(intent)
    decision_sig = _first_signature(decision)

    input_source = document.get("_agent_replay_source")
    if not isinstance(input_source, dict):
        input_source = {}

    return {
        "schema": "agent-replay.aps-authority-reconstruction.v2",
        "input_sha256": input_sha256,
        "adapter_validation": {
            "repository": APS_FIXTURE_REPOSITORY,
            "revision": APS_FIXTURE_REVISION,
            "fixture_family": APS_FIXTURE_FAMILY,
            "claim": "This identifies the fixture revision used to validate the adapter, not the provenance of the supplied input.",
        },
        "input_provenance": {
            "repository": input_source.get("repository"),
            "revision": input_source.get("revision"),
            "path": input_source.get("path"),
            "provenance_status": (
                "CALLER_SUPPLIED" if input_source else "UNKNOWN"
            ),
        },
        "external_conformance": {
            "source": "SUPPLIED_APS_CONFORMANCE_FIELDS",
            "fixture": document.get("fixture"),
            "outcome": document.get("expected"),
            "reasons": list(document.get("expectReasons") or []),
            "sub_results": list(document.get("expected_sub_results") or []),
            "authority_status": _external_authority_status(document, decision),
        },
        "identity": {
            "claimed_actor": claimed_actor,
            "intent_issuer": intent.get("issuer"),
            "intent_signer": intent_sig.get("signer"),
            "intent_signature_assessment": _receipt_authentication_status(
                document, intent, receipt_role="intent"
            ),
            "independent_authentication": "NOT_VERIFIED",
        },
        "authority": {
            "root_principal": path[0].get("issuer") if path else None,
            "delegation_path": path,
            "structural_binding": binding["status"],
            "independent_cryptographic_verification": "NOT_VERIFIED",
        },
        "policy": {
            "issuer": decision.get("issuer"),
            "signer": decision_sig.get("signer"),
            "signature_assessment": _receipt_authentication_status(
                document, decision, receipt_role="decision"
            ),
            "verdict": (decision.get("result") or {}).get("verdict"),
            "reason": (decision.get("result") or {}).get("reason"),
            "independent_authentication": "NOT_VERIFIED",
        },
        "binding": binding,
        "execution": execution,
        "observed_execution": execution["bound_events"],
        "execution_status": execution["status"],
        "evidence_boundary": {
            "permit_is_execution": False,
            "external_conformance_is_replay_verification": False,
            "independent_crypto_verification_performed": False,
            "claims": [
                "APS fixture outcomes are preserved as external conformance evidence.",
                "Replay independently checks structural references but does not independently verify Ed25519 or EIP-712 signatures.",
                "Execution is only promoted to fully bound evidence when action identity and actor identity are both present and consistent; missing actor identity remains partially bound.",
                "APS action-result receipts are treated as enforcement-boundary post-dispatch observations, not proof that an external effect occurred or settled.",
            ],
        },
    }
