from __future__ import annotations

from datetime import datetime
from typing import Any

from .model import CanonicalEvent


MODEL_VERSION = "ddc.evidence.v1"


def _parse_time(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _ddc_meta(event: CanonicalEvent) -> dict[str, Any]:
    raw = event.evidence.get("ddc_evidence")
    return raw if isinstance(raw, dict) else {}


def _event_record(event: CanonicalEvent) -> dict[str, Any]:
    meta = _ddc_meta(event)
    clocks = meta.get("clocks") if isinstance(meta.get("clocks"), dict) else {}
    availability = (
        meta.get("availability")
        if isinstance(meta.get("availability"), dict)
        else {}
    )
    source = meta.get("source") if isinstance(meta.get("source"), dict) else {}
    authority = (
        meta.get("authority")
        if isinstance(meta.get("authority"), dict)
        else {}
    )

    event_time = clocks.get("event_time") or event.timestamp
    evidence_created_at = clocks.get("evidence_created_at")
    evidence_available_at = clocks.get("evidence_available_at")
    decision_time = clocks.get("decision_time")

    decision_dt = _parse_time(decision_time)
    available_dt = _parse_time(evidence_available_at)
    available_at_decision: bool | None = None
    if decision_dt is not None and available_dt is not None:
        available_at_decision = available_dt <= decision_dt

    required = _list(meta.get("required_evidence"))
    consulted = _list(meta.get("consulted_evidence"))
    consulted_set = set(consulted)
    missing_required = [item for item in required if item not in consulted_set]

    if required and missing_required:
        decision_basis = "REQUIRED_EVIDENCE_NOT_CONSULTED"
    elif required:
        decision_basis = "REQUIRED_EVIDENCE_CONSULTED"
    else:
        decision_basis = "NO_REQUIREMENT_DECLARED"

    return {
        "event_id": event.event_id,
        "actor": event.actor,
        "claim": meta.get("claim"),
        "transition": meta.get("transition") or event.kind,
        "branch_id": meta.get("branch_id"),
        "evidence_class": meta.get("evidence_class"),
        "clocks": {
            "event_time": event_time,
            "evidence_created_at": evidence_created_at,
            "evidence_available_at": evidence_available_at,
            "decision_time": decision_time,
        },
        "available_at_decision": available_at_decision,
        "source": {
            "id": source.get("id"),
            "authority_scope": _list(source.get("authority_scope")),
            "independence_group": source.get("independence_group"),
        },
        "authority": {
            "valid_from": authority.get("valid_from"),
            "valid_until": authority.get("valid_until"),
            "claim_scope": _list(authority.get("claim_scope")),
        },
        "availability": {
            "existed": availability.get("existed"),
            "reachable": availability.get("reachable"),
            "discoverable": availability.get("discoverable"),
            "fresh": availability.get("fresh"),
            "accessible": availability.get("accessible"),
            "trusted": availability.get("trusted"),
            "consulted": availability.get("consulted"),
        },
        "required_evidence": required,
        "consulted_evidence": consulted,
        "missing_required_evidence": missing_required,
        "decision_basis": decision_basis,
        "provenance": _list(meta.get("provenance")),
        "transformation_chain": _list(meta.get("transformation_chain")),
        "causal_provenance": meta.get("causal_provenance"),
        "contradictions": _list(meta.get("contradictions")),
        "unresolved_assumptions": _list(meta.get("unresolved_assumptions")),
        "confidence": meta.get("confidence"),
    }


def build_evidence_model(events: list[CanonicalEvent]) -> dict[str, Any]:
    explicit = [
        _event_record(event)
        for event in events
        if _ddc_meta(event)
    ]

    contemporaneous = [
        record["event_id"]
        for record in explicit
        if record.get("evidence_class") == "contemporaneous"
    ]
    later = [
        record["event_id"]
        for record in explicit
        if record.get("evidence_class")
        in {"later_authoritative", "later_corroborative", "inferred"}
    ]
    retroactive_risk = [
        record["event_id"]
        for record in explicit
        if record.get("available_at_decision") is False
    ]
    decision_points = [
        {
            "event_id": record["event_id"],
            "actor": record["actor"],
            "decision_time": record["clocks"]["decision_time"],
            "available_at_decision": record["available_at_decision"],
            "required_evidence": record["required_evidence"],
            "consulted_evidence": record["consulted_evidence"],
            "missing_required_evidence": record["missing_required_evidence"],
            "decision_basis": record["decision_basis"],
            "unresolved_assumptions": record["unresolved_assumptions"],
        }
        for record in explicit
        if record["clocks"]["decision_time"]
        or record["required_evidence"]
        or record["consulted_evidence"]
    ]

    branches: dict[str, list[str]] = {}
    for record in explicit:
        branch_id = record.get("branch_id")
        if isinstance(branch_id, str) and branch_id:
            branches.setdefault(branch_id, []).append(record["event_id"])

    contradictions = [
        {
            "event_id": record["event_id"],
            "claims": record["contradictions"],
        }
        for record in explicit
        if record["contradictions"]
    ]

    return {
        "model_version": MODEL_VERSION,
        "scope": (
            "Evidence-model fields are caller-supplied metadata. Agent Replay preserves "
            "their boundaries but does not independently authenticate them unless another "
            "adapter explicitly does so."
        ),
        "records": explicit,
        "consequence_reconstruction": {
            "contemporaneous_event_ids": contemporaneous,
            "later_or_inferred_event_ids": later,
            "claim": (
                "Later evidence may strengthen what can be established about a past event "
                "without becoming evidence that was available at execution time."
            ),
        },
        "decision_reconstruction": {
            "decision_points": decision_points,
            "retroactive_knowledge_risk_event_ids": retroactive_risk,
            "claim": (
                "Historical decisions must be evaluated from evidence available to that "
                "actor at that decision point, including evidence it was required to obtain."
            ),
        },
        "branches": branches,
        "contradictions": contradictions,
        "invariants": {
            "dispatch_is_not_consequence": True,
            "chronology_is_not_causality": True,
            "later_truth_is_not_retroactive_knowledge": True,
            "certainty_is_claim_and_boundary_scoped": True,
            "unknown_is_valid": True,
        },
    }

