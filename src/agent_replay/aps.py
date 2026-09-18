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


def _delegation_chain_continuity(path: list[dict[str, Any]]) -> bool:
    if not path:
        return False
    if path[0].get("parent_delegation_id") not in (None, ""):
        return False
    for previous, current in zip(path, path[1:]):
        if current.get("parent_delegation_id") != previous.get("delegation_id"):
            return False
    return True


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
        return "FAILED_BY_EXTERNAL_CONFORMANCE"

    if signer != issuer:
        return "CLAIMED_SIGNER_MISMATCH"
    return "CLAIM_CONSISTENT_NOT_CRYPTOGRAPHICALLY_VERIFIED"


def _external_authority_disposition(document: dict[str, Any], decision: dict[str, Any]) -> str:
    reasons = set(document.get("expectReasons") or [])
    if "AUTH_DELEGATION_REVOKED" in reasons:
        return "REVOKED"
    if "AUTH_DELEGATION_EXPIRED" in reasons:
        return "EXPIRED"
    if "SIGNATURE_INVALID" in reasons and "HALT_AUTHORITY" in reasons:
        return "SIGNATURE_INVALID"
    if "POLICY_DENIED" in reasons or (decision.get("result") or {}).get("verdict") == "deny":
        return "DENIED"
    if document.get("expected") == "allowed":
        return "ALLOWED"
    if "HALT_AUTHORITY" in reasons:
        return "HALT"
    return "NOT_ESTABLISHED"


def _binding_status(
    *,
    action_ref_match: bool,
    receipt_link_match: bool,
    delegation_ref_match: bool,
    chain_continuity: bool,
) -> str:
    checks = (action_ref_match, receipt_link_match, delegation_ref_match, chain_continuity)
    if all(checks):
        return "COMPLETE"
    if any(checks):
        return "PARTIAL"
    return "BROKEN"


def _execution_binding(
    events: list[dict[str, Any]],
    *,
    action_ref: Any,
    claimed_actor: Any,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    if not events:
        return "NOT_OBSERVED", [], []

    action_bound: list[dict[str, Any]] = []
    actor_bound: list[dict[str, Any]] = []
    for item in events:
        if not isinstance(item, dict):
            continue
        if action_ref is not None and item.get("action_ref") == action_ref:
            action_bound.append(item)
            actor = item.get("actor") or item.get("subject_agent") or item.get("executor")
            if claimed_actor is not None and actor == claimed_actor:
                actor_bound.append(item)

    if actor_bound:
        return "EVIDENCE_ACTOR_BOUND", action_bound, actor_bound
    if action_bound:
        return "EVIDENCE_ACTION_BOUND", action_bound, []
    return "EVIDENCE_PRESENT_UNBOUND", [], []


def reconstruct_aps_fixture(
    document: dict[str, Any],
    *,
    input_sha256: str | None = None,
    input_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct APS authority evidence without upgrading unsupported claims."""
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

    path = _delegation_path(delegations)
    leaf = path[-1] if path else {}
    claimed_actor = intent.get("subject_agent") or intent.get("issuer")
    intent_sig = _first_signature(intent)
    decision_sig = _first_signature(decision)

    intent_action_ref = intent.get("action_ref")
    decision_action_ref = decision.get("action_ref")
    action_ref_match = bool(intent_action_ref) and intent_action_ref == decision_action_ref

    receipt_link_match = (
        bool(intent.get("receipt_id"))
        and decision.get("prev") == intent.get("receipt_id")
    )

    intent_delegation_ref = intent.get("delegation_ref")
    decision_delegation_ref = decision.get("delegation_ref")
    leaf_delegation_id = leaf.get("delegation_id")
    delegation_ref_match = (
        bool(intent_delegation_ref)
        and intent_delegation_ref == decision_delegation_ref
        and intent_delegation_ref == leaf_delegation_id
    )

    chain_continuity = _delegation_chain_continuity(path)
    binding_status = _binding_status(
        action_ref_match=action_ref_match,
        receipt_link_match=receipt_link_match,
        delegation_ref_match=delegation_ref_match,
        chain_continuity=chain_continuity,
    )

    raw_execution = envelope.get("execution_events")
    if raw_execution is None:
        raw_execution = document.get("execution_events")
    execution_events = [item for item in raw_execution if isinstance(item, dict)] if isinstance(raw_execution, list) else []
    execution_status, action_bound, actor_bound = _execution_binding(
        execution_events,
        action_ref=intent_action_ref,
        claimed_actor=claimed_actor,
    )

    provenance = input_provenance if isinstance(input_provenance, dict) else {}
    external_disposition = _external_authority_disposition(document, decision)

    cannot_establish = [
        "Independent Ed25519/EIP-712 cryptographic validity from this adapter alone.",
        "That APS external conformance assertions are true beyond the supplied fixture evidence.",
    ]
    if execution_status == "NOT_OBSERVED":
        cannot_establish.append(
            "Whether the action was dispatched or executed; no post-execution evidence is supplied."
        )
    elif execution_status == "EVIDENCE_PRESENT_UNBOUND":
        cannot_establish.append(
            "Whether supplied execution evidence belongs to this action; no execution event binds to the intent action_ref."
        )
    elif execution_status == "EVIDENCE_ACTION_BOUND":
        cannot_establish.append(
            "Whether the action-bound execution evidence was performed by the claimed actor."
        )
    else:
        cannot_establish.append(
            "Cryptographic authentication of the actor-bound execution evidence."
        )

    return {
        "schema": "agent-replay.aps-authority-reconstruction.v1",
        "source": {
            "system": "Agent Passport System",
            "fixture": document.get("fixture"),
            "adapter_tested_against": {
                "repository": APS_FIXTURE_REPOSITORY,
                "revision": APS_FIXTURE_REVISION,
                "fixture_family": APS_FIXTURE_FAMILY,
            },
            "input_provenance": {
                "repository": provenance.get("repository"),
                "revision": provenance.get("revision"),
                "path": provenance.get("path"),
                "sha256": input_sha256,
                "provenance_status": (
                    "SUPPLIED" if any(provenance.get(key) for key in ("repository", "revision", "path"))
                    else "UNKNOWN"
                ),
            },
            "external_conformance": {
                "outcome": document.get("expected"),
                "reasons": list(document.get("expectReasons") or []),
                "sub_results": list(document.get("expected_sub_results") or []),
                "authority_disposition": external_disposition,
                "scope": "SUPPLIED_APS_FIXTURE_ASSERTION",
            },
        },
        "identity": {
            "claimed_actor": claimed_actor,
            "intent_issuer": intent.get("issuer"),
            "intent_signer": intent_sig.get("signer"),
            "intent_authentication": _receipt_authentication_status(
                document, intent, receipt_role="intent"
            ),
        },
        "authority": {
            "root_principal": path[0].get("issuer") if path else None,
            "leaf_delegation_id": leaf_delegation_id,
            "delegation_path": path,
            "chain_continuity": chain_continuity,
            "evidence_status": (
                "CHAIN_BOUND" if binding_status == "COMPLETE"
                else "CHAIN_PRESENT_UNBOUND" if path
                else "MISSING"
            ),
            "external_conformance_disposition": external_disposition,
            "replay_verification": "NOT_INDEPENDENTLY_CRYPTOGRAPHICALLY_VERIFIED",
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
        "binding": {
            "status": binding_status,
            "action_ref": {
                "intent": intent_action_ref,
                "decision": decision_action_ref,
                "matched": action_ref_match,
            },
            "receipt_link": {
                "intent_receipt_id": intent.get("receipt_id"),
                "decision_prev": decision.get("prev"),
                "matched": receipt_link_match,
            },
            "delegation_ref": {
                "intent": intent_delegation_ref,
                "decision": decision_delegation_ref,
                "leaf": leaf_delegation_id,
                "matched": delegation_ref_match,
            },
            "delegation_chain_continuity": chain_continuity,
        },
        "execution": {
            "status": execution_status,
            "evidence_count": len(execution_events),
            "action_bound_count": len(action_bound),
            "actor_bound_count": len(actor_bound),
            "action_bound_events": action_bound,
            "actor_bound_events": actor_bound,
            "cryptographic_authentication": "NOT_VERIFIED",
        },
        "evidence_boundary": {
            "can_establish": [
                "The actor identity claimed by the supplied APS intent receipt.",
                "The signer identities asserted by supplied receipts.",
                "Structural action_ref, receipt-link, delegation-ref, and delegation-chain bindings.",
                "The supplied gateway policy decision.",
                "Whether supplied execution events structurally bind to the same action and claimed actor.",
            ],
            "cannot_establish": cannot_establish,
            "permit_is_execution": False,
            "monotonic_evidence_rule": (
                "Claims may only be upgraded when additional evidence supports the transition."
            ),
        },
    }
