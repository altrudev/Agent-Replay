from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SAFE_GAP_KEYS = {"type", "event_id", "kind", "basis", "effect"}
_SAFE_REVIEW_KEYS = {"prior_id", "title", "subjects", "falsification_test", "rationale", "disposition"}

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


def _actor_aliases(incident: dict[str, Any]) -> dict[str, str]:
    actors: list[str] = []
    for collection in ("timeline", "divergences", "causal_chain", "attribution"):
        for item in incident.get(collection) or []:
            actor = item.get("actor") if isinstance(item, dict) else None
            if isinstance(actor, str) and actor and actor not in actors:
                actors.append(actor)
    return {actor: f"actor-{index + 1}" for index, actor in enumerate(actors)}


def _safe_mismatches(items: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        # Preserve only the assertion field and boolean/numeric/string result values.
        expected = item.get("expected")
        observed = item.get("observed")
        if not isinstance(expected, (str, int, float, bool, type(None))):
            expected = "[REDACTED_COMPLEX_VALUE]"
        if not isinstance(observed, (str, int, float, bool, type(None))):
            observed = "[REDACTED_COMPLEX_VALUE]"
        out.append({"field": str(item.get("field", "")), "expected": expected, "observed": observed})
    return out


def _safe_event(item: dict[str, Any], aliases: dict[str, str], *, include_status: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "event_id": str(item.get("event_id", "")),
        "kind": str(item.get("kind", "")),
        "actor": aliases.get(str(item.get("actor", "")), "actor-unknown"),
        "parent_ids": [str(x) for x in item.get("parent_ids") or []],
        "mismatches": _safe_mismatches(item.get("mismatches")),
    }
    if include_status and "status" in item:
        out["status"] = str(item.get("status"))
    return out


def sanitize_incident(incident: dict[str, Any]) -> dict[str, Any]:
    aliases = _actor_aliases(incident)
    first = incident.get("first_provable_divergence")
    safe_first = _safe_event(first, aliases, include_status=False) if isinstance(first, dict) else None

    gaps: list[dict[str, Any]] = []
    for item in incident.get("evidence_gaps") or []:
        if not isinstance(item, dict):
            continue
        safe = {key: item[key] for key in _SAFE_GAP_KEYS if key in item}
        if "actor" in item:
            safe["actor"] = aliases.get(str(item["actor"]), "actor-unknown")
        gaps.append(safe)

    attribution: list[dict[str, Any]] = []
    for item in incident.get("attribution") or []:
        if not isinstance(item, dict):
            continue
        attribution.append({
            "actor": aliases.get(str(item.get("actor", "")), "actor-unknown"),
            "role": item.get("role"),
            "event_ids": [str(x) for x in item.get("event_ids") or []],
            "basis": item.get("basis"),
        })

    return {
        "schema": "agent-replay.public-share.v1",
        "source_schema": incident.get("schema"),
        "source_input_sha256": incident.get("input_sha256"),
        "source_canonical_sha256": incident.get("canonical_sha256"),
        "event_count": incident.get("event_count"),
        "expectation_coverage": incident.get("expectation_coverage"),
        "reconstruction_status": incident.get("reconstruction_status"),
        "evidence_completeness": incident.get("evidence_completeness"),
        "confidence": incident.get("confidence"),
        "timeline": [
            _safe_event(item, aliases)
            for item in incident.get("timeline") or []
            if isinstance(item, dict)
        ],
        "first_provable_divergence": safe_first,
        "divergences": [
            _safe_event(item, aliases, include_status=False)
            for item in incident.get("divergences") or []
            if isinstance(item, dict)
        ],
        "causal_chain": [
            {
                "event_id": str(item.get("event_id", "")),
                "kind": str(item.get("kind", "")),
                "actor": aliases.get(str(item.get("actor", "")), "actor-unknown"),
                "relationship": item.get("relationship"),
                "direct_parent_ids": [str(x) for x in item.get("direct_parent_ids") or []],
                "divergent_ancestor_ids": [str(x) for x in item.get("divergent_ancestor_ids") or []],
            }
            for item in incident.get("causal_chain") or []
            if isinstance(item, dict)
        ],
        "attribution": attribution,
        "evidence_gaps": gaps,
        "scope": {
            "expectations": incident.get("expectation_scope"),
            "attribution": incident.get("attribution_scope"),
            "confidence": incident.get("confidence_scope"),
            "completeness": incident.get("evidence_completeness_scope"),
        },
        "redaction": {
            "actors_pseudonymized": True,
            "timestamps_omitted": True,
            "raw_evidence_omitted": True,
            "trace_evidence_omitted": True,
            "infrastructure_metadata_omitted": True,
        },
    }


def sanitize_radial(review: dict[str, Any]) -> dict[str, Any]:
    source = review.get("engine_source") if isinstance(review.get("engine_source"), dict) else {}
    hypotheses = []
    for item in review.get("hypotheses") or []:
        if not isinstance(item, dict):
            continue
        hypotheses.append({key: item[key] for key in _SAFE_REVIEW_KEYS if key in item})
    return {
        "schema": "agent-replay.public-radial-review.v1",
        "engine": review.get("engine"),
        "engine_sha256": source.get("sha256") or review.get("engine_sha256"),
        "authoritative": False,
        "disposition": review.get("disposition"),
        "examined_nodes": review.get("examined_nodes"),
        "examined_edges": review.get("examined_edges"),
        "hypotheses": hypotheses,
        "redaction": {
            "engine_path_omitted": True,
            "feature_vectors_omitted": True,
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
            "proprietary_engine_source_included": False,
            "absolute_paths_included": False,
            "secrets_expected": False,
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
