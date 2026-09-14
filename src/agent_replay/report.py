from __future__ import annotations

from typing import Any


def _fmt(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    first = report.get("first_provable_divergence")

    lines.append("AGENT REPLAY INCIDENT")
    lines.append(f"Evidence SHA-256: {report['input_sha256']}")
    lines.append(f"Events: {report['event_count']}")
    lines.append(f"Reproducibility: {report['reproducibility']}")
    lines.append(f"Confidence: {report['confidence']}")
    lines.append("")

    lines.append("TIMELINE")
    for item in report["timeline"]:
        lines.append(
            f"- {item['timestamp']} {item['event_id']} {item['kind']} "
            f"[{item['status']}]"
        )

    lines.append("")
    if not first:
        lines.append("No provable divergence found.")
        return "\n".join(lines)

    lines.append("FIRST PROVABLE DIVERGENCE")
    lines.append(f"{first['timestamp']}  {first['event_id']}  {first['kind']}")
    lines.append(f"Actor: {first['actor']}")
    for mismatch in first["mismatches"]:
        lines.append(
            f"- {mismatch['field']}: expected={_fmt(mismatch['expected'])} "
            f"observed={_fmt(mismatch['observed'])}"
        )

    lines.append("")
    lines.append("CAUSAL / TEMPORAL CHAIN")
    for item in report["causal_chain"]:
        lines.append(
            f"- {item['timestamp']} {item['event_id']} {item['kind']} "
            f"[{item['relationship']}]"
        )

    lines.append("")
    lines.append("ATTRIBUTION")
    for item in report["attribution"]:
        lines.append(
            f"- {item['actor']}: {item['role']} "
            f"({', '.join(item['event_ids'])})"
        )
        lines.append(f"  basis: {item['basis']}")

    lines.append("")
    lines.append("EVIDENCE")
    for item in report["divergences"]:
        source = item.get("evidence", {}).get("source", "unknown")
        lines.append(
            f"- {item['event_id']}: {source}"
            f":{item.get('source_line', '?')}"
        )

    return "\n".join(lines)
