from __future__ import annotations

from typing import Any


def _fmt(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def _append_trace(lines: list[str], report: dict[str, Any]) -> None:
    trace = report.get("trace_evidence")
    if not isinstance(trace, dict):
        return
    verification = trace.get("verification", {})
    model = trace.get("model", {})
    runtime = trace.get("runtime", {})
    lines.append("")
    lines.append("TRACE EVIDENCE")
    lines.append(f"Verification: {verification.get('status', 'UNKNOWN')}")
    lines.append(f"Subject: {trace.get('subject')}")
    lines.append(f"Model: {model.get('provider')}/{model.get('model_id')}")
    lines.append(f"Runtime: {runtime.get('platform')}")
    lines.append(f"Scope: {verification.get('scope', '')}")


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    first = report.get("first_provable_divergence")
    coverage = report["expectation_coverage"]

    lines.append("AGENT REPLAY INCIDENT")
    lines.append(f"Evidence SHA-256: {report['input_sha256']}")
    lines.append(f"Canonical SHA-256: {report['canonical_sha256']}")
    lines.append(f"Events: {report['event_count']}")
    lines.append(
        "Expectation coverage: "
        f"{coverage['status']} "
        f"({coverage['events_with_expectations']}/{coverage['total_events']})"
    )
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
        if coverage["status"] in {"NO_EXPECTATIONS", "PARTIAL"}:
            lines.append(coverage["claim"])
        _append_trace(lines, report)
        return "\n".join(lines)

    lines.append("FIRST PROVABLE DIVERGENCE")
    lines.append(f"{first['timestamp']}  {first['event_id']}  {first['kind']}")
    lines.append(f"Actor label: {first['actor']}")
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
    lines.append(report["attribution_scope"])
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

    _append_trace(lines, report)
    return "\n".join(lines)
