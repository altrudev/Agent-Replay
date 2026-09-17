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
            actor = item.get("actor")
            if isinstance(actor, str):
                actors.append(actor)
            event_id = item.get("event_id")
            if isinstance(event_id, str):
                event_ids.append(event_id)
            kind = item.get("kind")
            if isinstance(kind, str):
                kinds.append(kind)
            for event_id_value in item.get("event_ids") or []:
                if isinstance(event_id_value, str):
                    event_ids.append(event_id_value)
            for parent in item.get("parent_ids") or item.get("direct_parent_ids") or []:
                if isinstance(parent, str):
                    event_ids.append(parent)
            for ancestor in item.get("divergent_ancestor_ids") or []:
                if isinstance(ancestor, str):
                    event_ids.append(ancestor)
            for mismatch in item.get("mismatches") or []:
                if isinstance(mismatch, dict) and isinstance(mismatch.get("field"), str):
                    fields.append(mismatch["field"])

    first = incident.get("first_provable_divergence")
    if isinstance(first, dict):
        if isinstance(first.get("actor"), str):
            actors.append(first["actor"])
        if isinstance(first.get("event_id"), str):
            event_ids.append(first["event_id"])
        if isinstance(first.get("kind"), str):
            kinds.append(first["kind"])
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


def _safe_mismatches(items: Any, field_aliases: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        field = str(item.get("field", ""))
        out.append({
            "assertion": field_aliases.get(field, "assertion-unknown"),
            "expected": _safe_scalar(item.get("expected")),
            "observed": _safe_scalar(item.get("observed")),
        })
    return out


def _alias_list(values: Any, aliases: dict[str, str]) -> list[str]:
    return [aliases.get(str(value), "event-unknown") for value in values or []]


def _safe_event(
    item: dict[str, Any],
    actor_aliases: dict[str, str],
    event_aliases: dict[str, str],
    kind_aliases: dict[str, str],
    field_aliases: dict[str, str],
    *,
    include_status: bool = True,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
        "kind": kind_aliases.get(str(item.get("kind", "")), "kind-unknown"),
        "actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"),
        "parents": _alias_list(item.get("parent_ids"), event_aliases),
        "mismatches": _safe_mismatches(item.get("mismatches"), field_aliases),
    }
    if include_status and "status" in item:
        out["status"] = str(item.get("status"))
    return out


def sanitize_incident(incident: dict[str, Any]) -> dict[str, Any]:
    actor_aliases, event_aliases, kind_aliases, field_aliases = _collect_aliases(incident)
    first = incident.get("first_provable_divergence")
    safe_first = (
        _safe_event(
            first,
            actor_aliases,
            event_aliases,
            kind_aliases,
            field_aliases,
            include_status=False,
        )
        if isinstance(first, dict)
        else None
    )

    coverage = incident.get("expectation_coverage")
    if isinstance(coverage, dict):
        safe_coverage = {
            "status": coverage.get("status"),
            "events_with_expectations": coverage.get("events_with_expectations"),
            "total_events": coverage.get("total_events"),
            "ratio": coverage.get("ratio"),
        }
    else:
        safe_coverage = None

    gaps: list[dict[str, Any]] = []
    for item in incident.get("evidence_gaps") or []:
        if not isinstance(item, dict):
            continue
        gaps.append({
            "type": item.get("type"),
            "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
        })

    attribution: list[dict[str, Any]] = []
    for item in incident.get("attribution") or []:
        if not isinstance(item, dict):
            continue
        attribution.append({
            "actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"),
            "role": item.get("role"),
            "events": _alias_list(item.get("event_ids"), event_aliases),
        })

    return {
        "schema": "agent-replay.public-share.v1",
        "source_schema": incident.get("schema"),
        "source_input_sha256": incident.get("input_sha256"),
        "source_canonical_sha256": incident.get("canonical_sha256"),
        "event_count": incident.get("event_count"),
        "expectation_coverage": safe_coverage,
        "reconstruction_status": incident.get("reconstruction_status"),
        "evidence_completeness": incident.get("evidence_completeness"),
        "confidence": incident.get("confidence"),
        "timeline": [
            _safe_event(item, actor_aliases, event_aliases, kind_aliases, field_aliases)
            for item in incident.get("timeline") or []
            if isinstance(item, dict)
        ],
        "first_provable_divergence": safe_first,
        "divergences": [
            _safe_event(
                item,
                actor_aliases,
                event_aliases,
                kind_aliases,
                field_aliases,
                include_status=False,
            )
            for item in incident.get("divergences") or []
            if isinstance(item, dict)
        ],
        "causal_chain": [
            {
                "event": event_aliases.get(str(item.get("event_id", "")), "event-unknown"),
                "kind": kind_aliases.get(str(item.get("kind", "")), "kind-unknown"),
                "actor": actor_aliases.get(str(item.get("actor", "")), "actor-unknown"),
                "relationship": item.get("relationship"),
                "direct_parents": _alias_list(item.get("direct_parent_ids"), event_aliases),
                "divergent_ancestors": _alias_list(item.get("divergent_ancestor_ids"), event_aliases),
            }
            for item in incident.get("causal_chain") or []
            if isinstance(item, dict)
        ],
        "attribution": attribution,
        "evidence_gaps": gaps,
        "scope": {
            "expectations": "CALLER_SUPPLIED_ASSERTIONS",
            "attribution": "EVIDENCE_LABELS_ONLY",
            "confidence": "STRUCTURAL_ONLY",
            "completeness": "STRUCTURAL_ONLY",
        },
        "redaction": {
            "actors_pseudonymized": True,
            "event_ids_pseudonymized": True,
            "event_kinds_pseudonymized": True,
            "assertion_fields_pseudonymized": True,
            "timestamps_omitted": True,
            "raw_evidence_omitted": True,
            "free_text_basis_omitted": True,
            "trace_evidence_omitted": True,
            "infrastructure_metadata_omitted": True,
        },
    }


def sanitize_radial(review: dict[str, Any]) -> dict[str, Any]:
    source = review.get("engine_source") if isinstance(review.get("engine_source"), dict) else {}
    hypotheses = [item for item in review.get("hypotheses") or [] if isinstance(item, dict)]
    prior_classes = {
        str(item.get("prior_id"))
        for item in hypotheses
        if item.get("prior_id") is not None
    }
    return {
        "schema": "agent-replay.public-radial-review.v1",
        "engine_sha256": source.get("sha256") or review.get("engine_sha256"),
        "authoritative": False,
        "disposition": review.get("disposition"),
        "examined_nodes": review.get("examined_nodes"),
        "examined_edges": review.get("examined_edges"),
        "candidate_count": len(hypotheses),
        "candidate_class_count": len(prior_classes),
        "redaction": {
            "engine_name_omitted": True,
            "engine_path_omitted": True,
            "prior_ids_omitted": True,
            "prior_titles_omitted": True,
            "subjects_omitted": True,
            "rationale_omitted": True,
            "falsification_templates_omitted": True,
            "feature_vectors_omitted": True,
            "scores_omitted": True,
            "thresholds_omitted": True,
            "source_code_omitted": True,
        },
    }


def _fail_if_sensitive(value: Any) -> None:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    for pattern in _SENSITIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(f"share bundle failed sensitive-data scan: {match.group(0)[:80]}")


def build_share_bundle(
    incident: dict[str, Any],
    radial: dict[str, Any] | None = None,
    *,
    agent_replay_commit: str | None = None,
) -> dict[str, Any]:
    public_incident = sanitize_incident(incident)
    public_radial = sanitize_radial(radial) if radial is not None else None
    bundle: dict[str, Any] = {
        "schema": "agent-replay.share-bundle.v1",
        "agent_replay_commit": agent_replay_commit,
        "incident": public_incident,
        "radial_review": public_radial,
        "sharing_policy": {
            "allowlist_export": True,
            "raw_source_included": False,
            "raw_evidence_included": False,
            "proprietary_engine_details_included": False,
            "absolute_paths_included": False,
            "sensitive_values_expected": False,
        },
    }
    _fail_if_sensitive(bundle)
    unsigned = _json_bytes(bundle)
    bundle["bundle_sha256"] = _sha256_bytes(unsigned)
    return bundle


def write_share_bundle(
    incident_path: str | Path,
    output_path: str | Path,
    *,
    radial_path: str | Path | None = None,
    agent_replay_commit: str | None = None,
) -> Path:
    incident = json.loads(Path(incident_path).read_text(encoding="utf-8"))
    radial = (
        json.loads(Path(radial_path).read_text(encoding="utf-8"))
        if radial_path is not None
        else None
    )
    bundle = build_share_bundle(
        incident,
        radial,
        agent_replay_commit=agent_replay_commit,
    )
    target = Path(output_path)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
