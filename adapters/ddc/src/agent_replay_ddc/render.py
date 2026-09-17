from __future__ import annotations

from typing import Any


def _subject_labels(
    incident: dict[str, Any],
    subject_ids: list[str],
) -> list[str]:
    timeline = {
        item.get("event_id"): item
        for item in incident.get("timeline", [])
        if isinstance(item, dict)
    }
    out = []
    for subject_id in subject_ids:
        item = timeline.get(subject_id)
        if item:
            out.append(
                f"{item.get('kind', 'unknown')} "
                f"({subject_id})"
            )
        else:
            out.append(subject_id)
    return out


def _group_hypotheses(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for item in hypotheses:
        prior_id = str(item.get("prior_id", "unknown"))
        if prior_id not in grouped:
            grouped[prior_id] = {
                "prior_id": prior_id,
                "title": item.get("title", prior_id),
                "score": item.get("score", 0),
                "rationale": item.get("rationale", ""),
                "falsification_test": item.get("falsification_test", ""),
                "occurrences": [],
            }
            order.append(prior_id)
        grouped[prior_id]["occurrences"].append(item.get("subjects") or [])

    return [grouped[prior_id] for prior_id in order]


def render_radial(
    incident: dict[str, Any],
    radial: dict[str, Any],
    *,
    limit: int = 10,
) -> str:
    hypotheses = radial.get("hypotheses") or []
    groups = _group_hypotheses(hypotheses)
    lines: list[str] = []

    lines.append("DDC RADIAL REVIEW")
    lines.append(f"Engine: {radial.get('engine', 'unknown')}")
    source = radial.get("engine_source")
    if isinstance(source, dict):
        if source.get("sha256"):
            lines.append(f"Engine SHA-256: {source['sha256']}")
        if source.get("path"):
            lines.append(f"Engine path: {source['path']}")
    lines.append(
        f"Candidates: {len(hypotheses)} "
        f"| Prior classes: {len(groups)} "
        f"| Nodes: {radial.get('examined_nodes', 0)} "
        f"| Edges: {radial.get('examined_edges', 0)}"
    )
    lines.append(
        f"Authoritative: {str(bool(radial.get('authoritative'))).lower()}"
    )
    lines.append(f"Disposition: {radial.get('disposition', 'unknown')}")
    lines.append("")

    if not hypotheses:
        lines.append("No Radial fault-prior candidates were produced.")
        return "\n".join(lines)

    for index, item in enumerate(groups[:limit], 1):
        score = item.get("score", 0)
        occurrences = item.get("occurrences") or []
        lines.append(f"{index}. {item.get('title', item.get('prior_id', 'candidate'))}")
        lines.append(f"   Prior: {item.get('prior_id', 'unknown')}")
        lines.append(
            f"   Score: {score:.3f}"
            if isinstance(score, (int, float))
            else f"   Score: {score}"
        )
        lines.append(f"   Matching edges: {len(occurrences)}")
        for occurrence in occurrences[:3]:
            labels = _subject_labels(incident, occurrence)
            lines.append("   Subjects: " + " -> ".join(labels))
        if len(occurrences) > 3:
            lines.append(f"   ... {len(occurrences) - 3} additional matching edges")
        lines.append(f"   Why: {item.get('rationale', '')}")
        lines.append(f"   Falsification: {item.get('falsification_test', '')}")
        lines.append("")

    if len(groups) > limit:
        lines.append(
            f"... {len(groups) - limit} additional prior classes omitted "
            f"from concise output."
        )

    lines.append(
        "Note: DDC Radial findings are non-authoritative CANDIDATE hypotheses."
    )
    lines.append(
        "Concise output groups matching edges by fault-prior class; --json preserves "
        "the complete per-edge hypothesis set."
    )
    lines.append(
        "Structural features may include caller-supplied evidence.radial / "
        "agent.replay.radial.* assertions; Agent Replay does not independently "
        "authenticate those hints."
    )
    return "\n".join(lines)
