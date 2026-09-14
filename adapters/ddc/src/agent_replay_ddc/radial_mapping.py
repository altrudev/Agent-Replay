from __future__ import annotations

from typing import Any


def _kind_dimensions(kind: str) -> set[str]:
    dims = {"state", "time", "provenance", "observability"}
    lowered = kind.lower()

    if "policy" in lowered:
        dims |= {"policy", "representation", "authority"}
    if "approval" in lowered or "auth" in lowered:
        dims |= {"authority", "policy"}
    if any(token in lowered for token in ("refund", "payment", "write", "commit", "tool")):
        dims |= {"action", "execution", "result", "consequence"}
    if "read" in lowered:
        dims |= {"dependency", "representation"}
    if "retry" in lowered or "recover" in lowered:
        dims |= {"recovery"}

    return dims


def _relation(kind: str) -> str:
    lowered = kind.lower()
    if "approval" in lowered or "auth" in lowered:
        return "authorizes"
    if "read" in lowered:
        return "reads"
    if "retry" in lowered:
        return "retries"
    if "recover" in lowered:
        return "recovers"
    if any(token in lowered for token in ("payment", "refund", "commit")):
        return "commits"
    if "write" in lowered or "tool" in lowered:
        return "writes"
    return "depends_on"


def _radial(event: dict[str, Any]) -> dict[str, Any]:
    evidence = event.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    value = evidence.get("radial")
    return value if isinstance(value, dict) else {}


def _bool_hint(meta: dict[str, Any], key: str, default: bool) -> bool:
    value = meta.get(key)
    return value if isinstance(value, bool) else default


def _float_hint(meta: dict[str, Any], key: str, default: float) -> float:
    value = meta.get(key)
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return default


def _string_hint(meta: dict[str, Any], key: str, default: str = "") -> str:
    value = meta.get(key)
    return value if isinstance(value, str) and value else default


def incident_to_radial_spec(incident: dict[str, Any]) -> dict[str, Any]:
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

        representation = _string_hint(
            radial,
            "representation",
            "agent-replay-canonical-v2",
        )

        nodes.append(
            {
                "id": event_id,
                "dimensions": sorted(_kind_dimensions(kind)),
                "mutable": _bool_hint(radial, "mutable", False),
                # Actor identity is not the same thing as authority identity.
                # Authority distance is only evidenced by an explicit hint.
                "authority": _string_hint(radial, "authority", ""),
                "representation": representation,
                "consequence": _float_hint(radial, "consequence", 0.0),
                "observable": bool(event.get("evidence")),
                "reversible": _bool_hint(radial, "reversible", True),
            }
        )

    by_id = {event["event_id"]: event for event in timeline}

    for event in timeline:
        dst = event["event_id"]
        parents = event.get("parent_ids") or []
        child_radial = _radial(event)

        for src in parents:
            if src not in by_id:
                raise ValueError(f"unknown parent event: {src}->{dst}")

            relation = _relation(str(event.get("kind", "")))

            edges.append(
                {
                    "src": src,
                    "dst": dst,
                    "relation": relation,
                    "time_gap": _float_hint(child_radial, "time_gap", 0.0),
                    "independently_mutable": _bool_hint(
                        child_radial, "independently_mutable", False
                    ),
                    "shared_atomic_boundary": _bool_hint(
                        child_radial, "shared_atomic_boundary", True
                    ),
                    "freshness_bound": _bool_hint(
                        child_radial, "freshness_bound", False
                    ),
                    "context_bound": _bool_hint(
                        child_radial, "context_bound", True
                    ),
                }
            )

    return {"nodes": nodes, "edges": edges}
