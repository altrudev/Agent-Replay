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


def _consequence(event: dict[str, Any]) -> float:
    if event.get("status") != "DIVERGENT":
        return 0.0
    kind = str(event.get("kind", "")).lower()
    if any(token in kind for token in ("payment", "refund", "delete", "commit")):
        return 0.9
    if "approval" in kind or "auth" in kind:
        return 0.8
    if "policy" in kind:
        return 0.7
    return 0.5


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
        actor = str(event.get("actor", "unknown"))
        nodes.append(
            {
                "id": event_id,
                "dimensions": sorted(_kind_dimensions(kind)),
                "mutable": True,
                "authority": actor,
                "representation": kind,
                "consequence": _consequence(event),
                "observable": bool(event.get("evidence")),
                "reversible": not any(
                    token in kind.lower()
                    for token in ("payment", "refund", "delete", "commit")
                ),
            }
        )

    by_id = {event["event_id"]: event for event in timeline}
    for event in timeline:
        dst = event["event_id"]
        parents = event.get("parent_ids") or []
        for src in parents:
            if src not in by_id:
                raise ValueError(f"unknown parent event: {src}->{dst}")

            parent = by_id[src]
            relation = _relation(str(event.get("kind", "")))
            different_actor = parent.get("actor") != event.get("actor")
            different_repr = parent.get("kind") != event.get("kind")

            edges.append(
                {
                    "src": src,
                    "dst": dst,
                    "relation": relation,
                    "time_gap": 0.5,
                    "independently_mutable": different_actor,
                    "shared_atomic_boundary": False,
                    "freshness_bound": False,
                    "context_bound": not different_repr,
                }
            )

    return {"nodes": nodes, "edges": edges}
