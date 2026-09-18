from __future__ import annotations

from typing import Any


def _kind_dimensions(kind: str) -> tuple[set[str], dict[str, str]]:
    dims = {"state", "time", "provenance", "observability"}
    provenance = {dim: "DEFAULT" for dim in dims}
    lowered = kind.lower()

    def inferred(values: set[str]) -> None:
        for value in values:
            dims.add(value)
            provenance[value] = "INFERRED"

    if "policy" in lowered:
        inferred({"policy", "representation", "authority"})
    if "approval" in lowered or "auth" in lowered:
        inferred({"authority", "policy"})
    if any(token in lowered for token in ("refund", "payment", "write", "commit", "tool")):
        inferred({"action", "execution", "result", "consequence"})
    if "read" in lowered:
        inferred({"dependency", "representation"})
    if "retry" in lowered or "recover" in lowered:
        inferred({"recovery"})
    return dims, provenance


def _radial(event: dict[str, Any]) -> dict[str, Any]:
    evidence = event.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    value = evidence.get("radial")
    return value if isinstance(value, dict) else {}


def _hint(meta: dict[str, Any], key: str, default: Any, validator) -> tuple[Any, str]:
    value = meta.get(key)
    if validator(value):
        return value, "EXPLICIT"
    return default, "DEFAULT"


def _bool_hint(meta: dict[str, Any], key: str, default: bool) -> tuple[bool, str]:
    return _hint(meta, key, default, lambda value: isinstance(value, bool))


def _float_hint(meta: dict[str, Any], key: str, default: float) -> tuple[float, str]:
    value = meta.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value))), "EXPLICIT"
    return default, "DEFAULT"


def _string_hint(meta: dict[str, Any], key: str, default: str = "") -> tuple[str, str]:
    value = meta.get(key)
    if isinstance(value, str) and value:
        return value, "EXPLICIT"
    return default, "DEFAULT"


def _edge_meta(radial: dict[str, Any], src: str) -> dict[str, Any]:
    raw_edges = radial.get("edges")
    if raw_edges is None:
        return radial
    if not isinstance(raw_edges, dict):
        raise ValueError("evidence.radial.edges must be an object")
    override = raw_edges.get(src)
    if override is None:
        return radial
    if not isinstance(override, dict):
        raise ValueError(f"evidence.radial.edges.{src} must be an object")
    merged = {key: value for key, value in radial.items() if key != "edges"}
    merged.update(override)
    return merged


def _incident_to_radial_spec(incident: dict[str, Any]) -> dict[str, Any]:
    if incident.get("schema") != "agent-replay.incident.v2":
        raise ValueError("DDC Radial adapter requires agent-replay.incident.v2")
    timeline = incident.get("timeline")
    if not isinstance(timeline, list):
        raise ValueError("incident timeline is required")

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    for event in timeline:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("timeline event_id must be a non-empty string")
        if event_id in seen:
            raise ValueError(f"duplicate timeline event_id: {event_id}")
        seen.add(event_id)

        kind = str(event.get("kind", "unknown"))
        radial = _radial(event)
        dimensions, dim_provenance = _kind_dimensions(kind)
        representation, representation_p = _string_hint(radial, "representation", "agent-replay-canonical-v2")
        mutable, mutable_p = _bool_hint(radial, "mutable", False)
        authority, authority_p = _string_hint(radial, "authority", "")
        consequence, consequence_p = _float_hint(radial, "consequence", 0.0)
        observable_default = bool(event.get("evidence"))
        observable, observable_p = _bool_hint(radial, "observable", observable_default)
        reversible, reversible_p = _bool_hint(radial, "reversible", True)

        nodes.append({
            "id": event_id,
            "dimensions": sorted(dimensions),
            "mutable": mutable,
            "authority": authority,
            "representation": representation,
            "consequence": consequence,
            "observable": observable,
            "reversible": reversible,
            "provenance": {
                "dimensions": dim_provenance,
                "mutable": mutable_p,
                "authority": authority_p,
                "representation": representation_p,
                "consequence": consequence_p,
                "observable": observable_p,
                "reversible": reversible_p,
            },
        })

    by_id = {event["event_id"]: event for event in timeline}
    for event in timeline:
        dst = event["event_id"]
        parents = event.get("parent_ids") or []
        child_radial = _radial(event)
        for src in parents:
            if src not in by_id:
                raise ValueError(f"unknown parent event: {src}->{dst}")
            edge_radial = _edge_meta(child_radial, src)
            relation, relation_p = _string_hint(edge_radial, "relation", "depends_on")
            time_gap, time_gap_p = _float_hint(edge_radial, "time_gap", 0.0)
            independently_mutable, independently_mutable_p = _bool_hint(edge_radial, "independently_mutable", False)
            shared_atomic_boundary, shared_atomic_boundary_p = _bool_hint(edge_radial, "shared_atomic_boundary", True)
            freshness_bound, freshness_bound_p = _bool_hint(edge_radial, "freshness_bound", False)
            context_bound, context_bound_p = _bool_hint(edge_radial, "context_bound", True)
            edges.append({
                "src": src,
                "dst": dst,
                "relation": relation,
                "time_gap": time_gap,
                "independently_mutable": independently_mutable,
                "shared_atomic_boundary": shared_atomic_boundary,
                "freshness_bound": freshness_bound,
                "context_bound": context_bound,
                "provenance": {
                    "relation": relation_p,
                    "time_gap": time_gap_p,
                    "independently_mutable": independently_mutable_p,
                    "shared_atomic_boundary": shared_atomic_boundary_p,
                    "freshness_bound": freshness_bound_p,
                    "context_bound": context_bound_p,
                },
            })

    return {"nodes": nodes, "edges": edges}



def _aps_to_radial_spec(report: dict[str, Any]) -> dict[str, Any]:
    identity = report.get("identity") if isinstance(report.get("identity"), dict) else {}
    authority = report.get("authority") if isinstance(report.get("authority"), dict) else {}
    policy = report.get("policy") if isinstance(report.get("policy"), dict) else {}
    binding = report.get("binding") if isinstance(report.get("binding"), dict) else {}
    execution = report.get("execution") if isinstance(report.get("execution"), dict) else {}

    def explicit_provenance(dimensions: list[str]) -> dict[str, Any]:
        return {
            "dimensions": {dimension: "EXPLICIT" for dimension in dimensions},
            "mutable": "EXPLICIT",
            "authority": "EXPLICIT",
            "representation": "EXPLICIT",
            "consequence": "EXPLICIT",
            "observable": "EXPLICIT",
            "reversible": "EXPLICIT",
        }

    nodes = [
        {
            "id": "aps:intent",
            "dimensions": ["authority", "identity", "provenance", "representation"],
            "mutable": False,
            "authority": str(identity.get("intent_issuer") or ""),
            "representation": "aps:action-intent",
            "consequence": 0.0,
            "observable": True,
            "reversible": True,
            "provenance": explicit_provenance(["authority", "identity", "provenance", "representation"]),
        },
        {
            "id": "aps:delegation",
            "dimensions": ["authority", "policy", "provenance", "time"],
            "mutable": False,
            "authority": str(authority.get("root_principal") or ""),
            "representation": "aps:delegation-chain",
            "consequence": 0.5,
            "observable": bool(authority.get("delegation_path")),
            "reversible": True,
            "provenance": explicit_provenance(["authority", "policy", "provenance", "time"]),
        },
        {
            "id": "aps:policy",
            "dimensions": ["authority", "policy", "provenance", "representation"],
            "mutable": False,
            "authority": str(policy.get("issuer") or ""),
            "representation": "aps:policy-decision",
            "consequence": 0.7,
            "observable": True,
            "reversible": True,
            "provenance": explicit_provenance(["authority", "policy", "provenance", "representation"]),
        },
        {
            "id": "aps:execution",
            "dimensions": ["action", "execution", "provenance", "observability"],
            "mutable": False,
            "authority": "",
            "representation": "aps:execution-evidence",
            "consequence": 1.0,
            "observable": bool(execution.get("events")),
            "reversible": False,
            "provenance": explicit_provenance(["action", "execution", "provenance", "observability"]),
        },
    ]

    checks = binding.get("checks") if isinstance(binding.get("checks"), dict) else {}
    edges = [
        {
            "src": "aps:delegation", "dst": "aps:intent", "relation": "authorizes",
            "time_gap": 0.0, "independently_mutable": True,
            "shared_atomic_boundary": False, "freshness_bound": True,
            "context_bound": bool(checks.get("delegation_ref") and checks.get("delegation_chain")),
            "provenance": {key: "EXPLICIT" for key in ("relation","time_gap","independently_mutable","shared_atomic_boundary","freshness_bound","context_bound")},
        },
        {
            "src": "aps:intent", "dst": "aps:policy", "relation": "evaluated_by",
            "time_gap": 0.0, "independently_mutable": True,
            "shared_atomic_boundary": False, "freshness_bound": True,
            "context_bound": bool(checks.get("action_ref") and checks.get("receipt_link") and checks.get("delegation_ref")),
            "provenance": {key: "EXPLICIT" for key in ("relation","time_gap","independently_mutable","shared_atomic_boundary","freshness_bound","context_bound")},
        },
        {
            "src": "aps:policy", "dst": "aps:execution", "relation": "precedes",
            "time_gap": 0.0, "independently_mutable": True,
            "shared_atomic_boundary": False, "freshness_bound": False,
            "context_bound": execution.get("status") == "EXECUTION_BOUND_TO_ACTION",
            "provenance": {key: "EXPLICIT" for key in ("relation","time_gap","independently_mutable","shared_atomic_boundary","freshness_bound","context_bound")},
        },
    ]
    return {"nodes": nodes, "edges": edges}


def incident_to_radial_spec(incident: dict[str, Any]) -> dict[str, Any]:
    schema = incident.get("schema")
    if schema == "agent-replay.incident.v2":
        return _incident_to_radial_spec(incident)
    if schema == "agent-replay.aps-authority-reconstruction.v2":
        return _aps_to_radial_spec(incident)
    raise ValueError(f"DDC Radial adapter does not support schema: {schema!r}")
