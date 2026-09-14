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


def render_radial(
    incident: dict[str, Any],
    radial: dict[str, Any],
    *,
    limit: int = 10,
) -> str:
    hypotheses = radial.get("hypotheses") or []
    lines: list[str] = []

    lines.append("DDC RADIAL REVIEW")
    lines.append(f"Engine: {radial.get('engine', 'unknown')}")
    lines.append(
        f"Candidates: {len(hypotheses)} "
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

    for index, item in enumerate(hypotheses[:limit], 1):
        score = item.get("score", 0)
        lines.append(f"{index}. {item.get('title', item.get('prior_id', 'candidate'))}")
        lines.append(f"   Prior: {item.get('prior_id', 'unknown')}")
        lines.append(f"   Score: {score:.3f}" if isinstance(score, (int, float)) else f"   Score: {score}")
        labels = _subject_labels(incident, item.get("subjects") or [])
        lines.append("   Subjects:")
        for label in labels:
            lines.append(f"     - {label}")
        lines.append(f"   Why: {item.get('rationale', '')}")
        lines.append(f"   Falsification: {item.get('falsification_test', '')}")
        lines.append("")

    if len(hypotheses) > limit:
        lines.append(
            f"... {len(hypotheses) - limit} additional candidates omitted "
            f"from concise output."
        )

    lines.append(
        "Note: DDC Radial findings are non-authoritative CANDIDATE hypotheses."
    )
    return "\n".join(lines)
