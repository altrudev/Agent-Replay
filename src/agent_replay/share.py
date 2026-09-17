from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SENSITIVE_PATTERNS = (
    re.compile(r"(?:^|[^A-Za-z0-9_])(Bearer\s+[A-Za-z0-9._~+/=-]+)", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*[^\s,;]+", re.IGNORECASE),
    re.compile(r"/home/[^\s\"']+"),
    re.compile(r"(?:^|[^0-9])(?:\d{1,3}\.){3}\d{1,3}(?:[^0-9]|$)"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_aliases(values: list[str], prefix: str) -> dict[str, str]:
    unique: list[str] = []
    for value in values:
        if value and value not in unique:
            unique.append(value)
    return {value: f"{prefix}-{index + 1}" for index, value in enumerate(unique)}


def _collect_aliases(incident: dict[str, Any]) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    actors: list[str] = []
    event_ids: list[str] = []
    kinds: list[str] = []
    fields: list[str] = []
    for collection in ("timeline", "divergences", "causal_chain", "attribution", "evidence_gaps"):
        for item in incident.get(collection) or []:
            if not isinstance(item, dict):
                continue
            for key, target in (("actor", actors), ("event_id", event_ids), ("kind", kinds)):
                value = item.get(key)
                if isinstance(value, str):
                    target.append(value)
            for key in ("event_ids", "parent_ids", "direct_parent_ids", "divergent_ancestor_ids"):
                for value in item.get(key) or []:
                    if isinstance(value, str):
                        event_ids.append(value)
            for mismatch in item.get("mismatches") or []:
                if isinstance(mismatch, dict) and isinstance(mismatch.get("field"), str):
                    fields.append(mismatch["field"])

    first = incident.get("first_provable_divergence")
    if isinstance(first, dict):
        for key, target in (("actor", actors), ("event_id", event_ids), ("kind", kinds)):
            value = first.get(key)
            if isinstance(value, str):
                target.append(value)
        for parent in first.get("parent_ids") or []:
            if isinstance(parent, str):
                event_ids.append(parent)
        for mismatch in first.get("mismatches") or []:
            if isinstance(mismatch, dict) and isinstance(mismatch.get("field"), str):
                fields.append(mismatch["field"])

    return (
        _stable_aliases(actors, "actor"),
        _stable_aliases(event_ids, "event"),
        _stable_aliases(kinds, "kind"),
        _stable_aliases(fields, "assertion"),
    )


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return "[REDACTED_COMPLEX_VALUE]"


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _safe_mismatches(items: Any, field_aliases: dict[str, str], *, include_values: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        field = str(item.get("field", ""))
        expected = item.get("expected")
        observed = item.get("observed")
        row: dict[str, Any] = {
            "assertion": field_aliases.get(field, "assertion-unknown"),
            "expected_type": _value_type(expected),
            "observed_type": _value_type(observed),
            "changed": expected != observed,
        }
        if include_values:
            row["expected"] = _safe_scalar(expected)
            row["observed"] = _safe_scalar(observed)
        out.append(row)
    return out


def _alias_list(values: Any, aliases: dict[str, str]) -> list[str]:
    return [aliases.get(str(value), "event-unknown") for value in values or []]


def _safe_event(item: dict[str, Any], actor_aliases: dict[str, str], event_aliases: dict[str, str], kind_aliases: dict[str, str], field_aliases: dict[str, str], *, include_values: bool, include_status: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
        "kind": kind_aliases.get(str(item.get("kind", "")), "kind-unknown"),
        "actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"),
        "parents": _alias_list(item.get("parent_ids"), event_aliases),
        "mismatches": _safe_mismatches(item.get("mismatches"), field_aliases, include_values=include_values),
    }
    if include_status and "status" in item:
        out["status"] = str(item.get("status"))
    return out


def _safe_boundary(
    boundary: Any,
    event_aliases: dict[str, str],
    kind_aliases: dict[str, str],
) -> dict[str, Any] | None:
    if not isinstance(boundary, dict):
        return None
    events: list[dict[str, Any]] = []
    for item in boundary.get("events") or []:
        if not isinstance(item, dict):
            continue
        policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
        receipt = item.get("revocation_receipt") if isinstance(item.get("revocation_receipt"), dict) else {}
        events.append({
            "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
            "kind": kind_aliases.get(str(item.get("kind", "")), "kind-unknown"),
            "policy_status": policy.get("status"),
            "revocation_receipt_status": receipt.get("status"),
        })
    return {
        "schema": boundary.get("schema"),
        "trust_store_configured": bool(boundary.get("trust_store_configured")),
        "authenticated_expectation_events": boundary.get("authenticated_expectation_events", 0),
        "verified_revocation_receipts": boundary.get("verified_revocation_receipts", 0),
        "replay_scope": boundary.get("replay_scope"),
        "events": events,
        "proof_material_included": False,
        "scope": (
            "Verification status is exported, but signed payloads, signatures, key identifiers, "
            "and trusted public keys are omitted by default and cannot be re-verified from this bundle alone."
        ),
    }


def sanitize_incident(incident: dict[str, Any], *, include_values: bool = False) -> dict[str, Any]:
    actor_aliases, event_aliases, kind_aliases, field_aliases = _collect_aliases(incident)
    first = incident.get("first_provable_divergence")
    safe_first = _safe_event(first, actor_aliases, event_aliases, kind_aliases, field_aliases, include_values=include_values, include_status=False) if isinstance(first, dict) else None
    coverage = incident.get("expectation_coverage")
    safe_coverage = ({
        "status": coverage.get("status"),
        "events_with_expectations": coverage.get("events_with_expectations"),
        "total_events": coverage.get("total_events"),
        "ratio": coverage.get("ratio"),
    } if isinstance(coverage, dict) else None)

    gaps = [
        {"type": item.get("type"), "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown")}
        for item in incident.get("evidence_gaps") or [] if isinstance(item, dict)
    ]
    attribution = [
        {"actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"), "role": item.get("role"), "events": _alias_list(item.get("event_ids"), event_aliases)}
        for item in incident.get("attribution") or [] if isinstance(item, dict)
    ]

    safe_boundary = _safe_boundary(
        incident.get("boundary_evidence"),
        event_aliases,
        kind_aliases,
    )

    return {
        "schema": "agent-replay.public-share.v1",
        "source_schema": incident.get("schema"),
        "source_input_sha256": incident.get("input_sha256"),
        "source_canonical_sha256": incident.get("canonical_sha256"),
        "event_count": incident.get("event_count"),
        "expectation_coverage": safe_coverage,
        "boundary_evidence": safe_boundary,
        "reconstruction_status": incident.get("reconstruction_status"),
        "evidence_completeness": incident.get("evidence_completeness"),
        "confidence": incident.get("confidence"),
        "timeline": [_safe_event(item, actor_aliases, event_aliases, kind_aliases, field_aliases, include_values=include_values) for item in incident.get("timeline") or [] if isinstance(item, dict)],
        "first_provable_divergence": safe_first,
        "divergences": [_safe_event(item, actor_aliases, event_aliases, kind_aliases, field_aliases, include_values=include_values, include_status=False) for item in incident.get("divergences") or [] if isinstance(item, dict)],
        "causal_chain": [{
            "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
            "kind": kind_aliases.get(str(item.get("kind", "")), "kind-unknown"),
            "actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"),
            "relationship": item.get("relationship"),
            "direct_parents": _alias_list(item.get("direct_parent_ids"), event_aliases),
            "divergent_ancestors": _alias_list(item.get("divergent_ancestor_ids"), event_aliases),
        } for item in incident.get("causal_chain") or [] if isinstance(item, dict)],
        "attribution": attribution,
        "evidence_gaps": gaps,
        "scope": {
            "expectations": "CRYPTOGRAPHIC_WHEN_VERIFIED_ELSE_CALLER_SUPPLIED",
            "boundary_receipts": "SIGNED_WHEN_VERIFIED",
            "attribution": "EVIDENCE_LABELS_ONLY",
            "confidence": "STRUCTURAL_ONLY",
            "completeness": "STRUCTURAL_ONLY",
        },
        "redaction": {
            "actors_pseudonymized": True, "event_ids_pseudonymized": True,
            "event_kinds_pseudonymized": True, "assertion_fields_pseudonymized": True,
            "assertion_values_included": include_values, "timestamps_omitted": True,
            "raw_evidence_omitted": True, "free_text_basis_omitted": True,
            "trace_evidence_omitted": True, "boundary_proof_material_omitted": True,
            "trusted_key_identifiers_omitted": True, "infrastructure_metadata_omitted": True,
        },
    }


def sanitize_radial(review: dict[str, Any]) -> dict[str, Any]:
    source = review.get("engine_source") if isinstance(review.get("engine_source"), dict) else {}
    hypotheses = [item for item in review.get("hypotheses") or [] if isinstance(item, dict)]
    prior_classes = {str(item.get("prior_id")) for item in hypotheses if item.get("prior_id") is not None}
    return {
        "schema": "agent-replay.public-radial-review.v1",
        "engine_sha256": source.get("sha256") or review.get("engine_sha256"),
        "authoritative": False,
        "disposition": review.get("disposition"),
        "examined_nodes": review.get("examined_nodes"),
        "examined_edges": review.get("examined_edges"),
        "candidate_count": len(hypotheses),
        "candidate_class_count": len(prior_classes),
        "mapping_provenance": review.get("mapping_provenance"),
        "redaction": {
            "engine_name_omitted": True, "engine_path_omitted": True,
            "prior_ids_omitted": True, "prior_titles_omitted": True,
            "subjects_omitted": True, "rationale_omitted": True,
            "falsification_templates_omitted": True, "feature_vectors_omitted": True,
            "scores_omitted": True, "thresholds_omitted": True, "source_code_omitted": True,
        },
    }


def _fail_if_sensitive(value: Any) -> None:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    for pattern in _SENSITIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(f"share bundle failed sensitive-data scan: {match.group(0)[:80]}")


def build_share_bundle(incident: dict[str, Any], radial: dict[str, Any] | None = None, *, agent_replay_commit: str | None = None, include_values: bool = False) -> dict[str, Any]:
    public_incident = sanitize_incident(incident, include_values=include_values)
    public_radial = sanitize_radial(radial) if radial is not None else None
    bundle: dict[str, Any] = {
        "schema": "agent-replay.share-bundle.v1",
        "agent_replay_commit": agent_replay_commit,
        "incident": public_incident,
        "radial_review": public_radial,
        "sharing_policy": {
            "allowlist_export": True, "raw_source_included": False,
            "raw_evidence_included": False, "proprietary_engine_details_included": False,
            "absolute_paths_included": False, "assertion_values_included": include_values,
            "sensitive_values_expected": False,
        },
    }
    _fail_if_sensitive(bundle)
    bundle["bundle_sha256"] = _sha256_bytes(_json_bytes(bundle))
    return bundle


def write_share_bundle(incident_path: str | Path, output_path: str | Path, *, radial_path: str | Path | None = None, agent_replay_commit: str | None = None, include_values: bool = False) -> Path:
    incident = json.loads(Path(incident_path).read_text(encoding="utf-8"))
    radial = json.loads(Path(radial_path).read_text(encoding="utf-8")) if radial_path is not None else None
    bundle = build_share_bundle(incident, radial, agent_replay_commit=agent_replay_commit, include_values=include_values)
    target = Path(output_path)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
