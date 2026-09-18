from __future__ import annotations

from typing import Any


APS_FIXTURE_REVISION = "6e8b05b202d727ef18e84e100fc31db11f36529f"


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


def _authority_status(document: dict[str, Any], decision: dict[str, Any]) -> str:
    reasons = set(document.get("expectReasons") or [])
    if "AUTH_DELEGATION_REVOKED" in reasons:
        return "REVOKED"
    if "AUTH_DELEGATION_EXPIRED" in reasons:
        return "EXPIRED"
    if "SIGNATURE_INVALID" in reasons and "HALT_AUTHORITY" in reasons:
        return "UNVERIFIED"
    if "POLICY_DENIED" in reasons or (decision.get("result") or {}).get("verdict") == "deny":
        return "DENIED"
    if document.get("expected") == "allowed":
        return "VALID"
    if "HALT_AUTHORITY" in reasons:
        return "INVALID"
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
        return "FAILED_BY_FIXTURE_ORACLE"

    if signer != issuer:
        return "CLAIMED_SIGNER_MISMATCH"

    # Agent Replay preserves APS's conformance result but does not independently
    # perform Ed25519/EIP-712 cryptographic verification in this adapter.
    return "CONSISTENT_WITH_FIXTURE"


def reconstruct_aps_fixture(document: dict[str, Any]) -> dict[str, Any]:
    """Map an APS oracle-safety-check fixture into authority-safe Replay evidence.

    This adapter intentionally separates claimed identity, receipt signer,
    delegated authority, policy decision, and observed execution. It consumes
    the APS fixture's conformance outcome as external evidence and never treats
    a pre-dispatch permit as proof that execution occurred.
    """
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

    intent_sig = _first_signature(intent)
    decision_sig = _first_signature(decision)
    intent_action_ref = intent.get("action_ref")
    decision_action_ref = decision.get("action_ref")
    action_ref_match = bool(intent_action_ref) and intent_action_ref == decision_action_ref

    path = _delegation_path(delegations)
    authority_root = path[0].get("issuer") if path else None

    explicit_execution = envelope.get("execution_events")
    if explicit_execution is None:
        explicit_execution = document.get("execution_events")
    if not isinstance(explicit_execution, list):
        explicit_execution = []

    authority_status = _authority_status(document, decision)

    can_establish = [
        "The action identity claimed by the APS intent receipt.",
        "The signer identity asserted by each supplied receipt.",
        "The delegation path carried by the supplied APS envelope.",
        "The gateway policy decision and whether it binds to the same action_ref.",
    ]
    cannot_establish = [
        "Independent cryptographic validity beyond the APS fixture oracle result.",
    ]
    if not explicit_execution:
        cannot_establish.append(
            "Whether the action was dispatched or executed; no post-execution event is supplied."
        )

    return {
        "schema": "agent-replay.aps-authority-reconstruction.v1",
        "source": {
            "system": "Agent Passport System",
            "fixture": document.get("fixture"),
            "pinned_revision": APS_FIXTURE_REVISION,
            "external_conformance_outcome": document.get("expected"),
            "external_conformance_reasons": list(document.get("expectReasons") or []),
            "external_sub_results": list(document.get("expected_sub_results") or []),
        },
        "identity": {
            "claimed_actor": intent.get("subject_agent") or intent.get("issuer"),
            "intent_issuer": intent.get("issuer"),
            "intent_signer": intent_sig.get("signer"),
            "intent_authentication": _receipt_authentication_status(
                document, intent, receipt_role="intent"
            ),
        },
        "authority": {
            "root_principal": authority_root,
            "delegation_path": path,
            "status": authority_status,
            "delegation_ref": intent.get("delegation_ref"),
        },
        "policy": {
            "issuer": decision.get("issuer"),
            "signer": decision_sig.get("signer"),
            "authentication": _receipt_authentication_status(
                document, decision, receipt_role="decision"
            ),
            "verdict": (decision.get("result") or {}).get("verdict"),
            "reason": (decision.get("result") or {}).get("reason"),
        },
        "action_binding": {
            "intent_action_ref": intent_action_ref,
            "decision_action_ref": decision_action_ref,
            "matched": action_ref_match,
            "decision_prev": decision.get("prev"),
            "intent_receipt_id": intent.get("receipt_id"),
        },
        "observed_execution": explicit_execution,
        "execution_status": "OBSERVED" if explicit_execution else "NOT_OBSERVED",
        "evidence_boundary": {
            "can_establish": can_establish,
            "cannot_establish": cannot_establish,
            "permit_is_execution": False,
        },
    }
