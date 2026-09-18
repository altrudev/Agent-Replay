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


def _aps_to_radial_spec(report: dict[str, Any]) -> dict[str, Any]:
    authority = report.get("authority") if isinstance(report.get("authority"), dict) else {}
    identity = report.get("identity") if isinstance(report.get("identity"), dict) else {}
    policy = report.get("policy") if isinstance(report.get("policy"), dict) else {}
    binding = report.get("binding") if isinstance(report.get("binding"), dict) else {}
    execution = report.get("execution") if isinstance(report.get("execution"), dict) else {}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def node(node_id: str, dimensions: set[str], *, authority_value: str = "", observable: bool = True) -> None:
        nodes.append({
            "id": node_id,
            "dimensions": sorted(dimensions),
            "mutable": False,
            "authority": authority_value,
            "representation": "agent-replay-aps-authority-v1",
            "consequence": 0.0,
            "observable": observable,
            "reversible": True,
            "provenance": {
                "dimensions": {dim: "EXPLICIT" for dim in dimensions},
                "mutable": "DEFAULT",
                "authority": "EXPLICIT" if authority_value else "DEFAULT",
                "representation": "EXPLICIT",
                "consequence": "DEFAULT",
                "observable": "EXPLICIT",
                "reversible": "DEFAULT",
            },
        })

    root = authority.get("root_principal")
    if root:
        node("aps:principal", {"identity", "authority", "provenance"}, authority_value=str(root))

    delegation_path = authority.get("delegation_path") or []
    previous = "aps:principal" if root else None
    for index, link in enumerate(delegation_path, 1):
        node_id = f"aps:delegation:{index}"
        node(node_id, {"authority", "delegation", "time", "provenance"}, authority_value=str(link.get("issuer") or ""))
        if previous:
            edges.append({
                "src": previous, "dst": node_id, "relation": "delegates",
                "time_gap": 0.0, "independently_mutable": False,
                "shared_atomic_boundary": False, "freshness_bound": True,
                "context_bound": True,
                "provenance": {
                    "relation": "EXPLICIT", "time_gap": "DEFAULT",
                    "independently_mutable": "DEFAULT", "shared_atomic_boundary": "DEFAULT",
                    "freshness_bound": "EXPLICIT", "context_bound": "EXPLICIT",
                },
            })
        previous = node_id

    node("aps:intent", {"identity", "action", "authority", "representation", "provenance"}, authority_value=str(identity.get("claimed_actor") or ""))
    if previous and (binding.get("delegation_ref") or {}).get("matched"):
        edges.append({
            "src": previous, "dst": "aps:intent", "relation": "authorizes_claim",
            "time_gap": 0.0, "independently_mutable": False,
            "shared_atomic_boundary": False, "freshness_bound": True,
            "context_bound": True,
            "provenance": {
                "relation": "EXPLICIT", "time_gap": "DEFAULT",
                "independently_mutable": "DEFAULT", "shared_atomic_boundary": "DEFAULT",
                "freshness_bound": "EXPLICIT", "context_bound": "EXPLICIT",
            },
        })

    node("aps:policy", {"policy", "authority", "decision", "representation", "provenance"}, authority_value=str(policy.get("issuer") or ""))
    if (binding.get("receipt_link") or {}).get("matched"):
        edges.append({
            "src": "aps:intent", "dst": "aps:policy", "relation": "receipt_precedes",
            "time_gap": 0.0, "independently_mutable": True,
            "shared_atomic_boundary": False, "freshness_bound": True,
            "context_bound": True,
            "provenance": {
                "relation": "EXPLICIT", "time_gap": "DEFAULT",
                "independently_mutable": "INFERRED", "shared_atomic_boundary": "DEFAULT",
                "freshness_bound": "EXPLICIT", "context_bound": "EXPLICIT",
            },
        })

    for index, event in enumerate(execution.get("action_bound_events") or [], 1):
        node_id = f"aps:execution:{index}"
        node(node_id, {"execution", "action", "result", "consequence", "provenance"}, authority_value=str(event.get("actor") or event.get("executor") or ""))
        edges.append({
            "src": "aps:policy", "dst": node_id, "relation": "precedes_execution_evidence",
            "time_gap": 0.0, "independently_mutable": True,
            "shared_atomic_boundary": False, "freshness_bound": False,
            "context_bound": True,
            "provenance": {
                "relation": "EXPLICIT", "time_gap": "DEFAULT",
                "independently_mutable": "INFERRED", "shared_atomic_boundary": "DEFAULT",
                "freshness_bound": "DEFAULT", "context_bound": "EXPLICIT",
            },
        })

    return {"nodes": nodes, "edges": edges}


def incident_to_radial_spec(incident: dict[str, Any]) -> dict[str, Any]:
    if incident.get("schema") == "agent-replay.aps-authority-reconstruction.v1":
        return _aps_to_radial_spec(incident)
    if incident.get("schema") != "agent-replay.incident.v2":
        raise ValueError("DDC Radial adapter requires an Agent Replay incident or APS authority reconstruction")
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
