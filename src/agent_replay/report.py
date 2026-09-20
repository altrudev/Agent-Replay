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
    verifier = trace.get("verifier_package")
    if isinstance(verifier, dict):
        lines.append(
            f"Verifier: {verifier.get('name')}/{verifier.get('version')}"
        )
    if trace.get("record_sha256"):
        lines.append(f"TRACE record SHA-256: {trace.get('record_sha256')}")
    if trace.get("trusted_key_sha256"):
        lines.append(f"Trusted key SHA-256: {trace.get('trusted_key_sha256')}")
    lines.append(f"Scope: {verification.get('scope', '')}")


def _append_evidence_gaps(lines: list[str], report: dict[str, Any]) -> None:
    gaps = report.get("evidence_gaps", [])
    lines.append("")
    lines.append("EVIDENCE COMPLETENESS")
    lines.append(f"Status: {report.get('evidence_completeness', 'UNKNOWN')}")
    scope = report.get("evidence_completeness_scope")
    if scope:
        lines.append(f"Scope: {scope}")
    if not gaps:
        lines.append("- No structural evidence gaps identified in supplied assertions.")
        return
    for gap in gaps:
        lines.append(
            f"- {gap.get('event_id', '?')} {gap.get('type', 'UNKNOWN')}: "
            f"{gap.get('basis', '')}"
        )
        if gap.get("effect"):
            lines.append(f"  effect: {gap['effect']}")



def _render_aps_text(report: dict[str, Any]) -> str:
    validation = report.get("adapter_validation", {})
    provenance = report.get("input_provenance", {})
    external = report.get("external_conformance", {})
    identity = report.get("identity", {})
    authority = report.get("authority", {})
    policy = report.get("policy", {})
    binding = report.get("binding", {})
    execution = report.get("execution", {})
    boundary = report.get("evidence_boundary", {})
    lines = [
        "AGENT REPLAY APS AUTHORITY RECONSTRUCTION",
        f"Fixture: {external.get('fixture')}",
        f"Adapter validated against: {validation.get('repository')}@{validation.get('revision')}",
        f"Input provenance: {provenance.get('provenance_status')}",
        f"Input SHA-256: {report.get('input_sha256')}",
        "",
        "EXTERNAL APS CONFORMANCE",
        f"Outcome: {external.get('outcome')}",
        f"Authority status: {external.get('authority_status')}",
        "",
        "IDENTITY",
        f"Claimed actor: {identity.get('claimed_actor')}",
        f"Intent signer: {identity.get('intent_signer')}",
        f"Signer assessment: {identity.get('intent_signature_assessment')}",
        f"Independent authentication: {identity.get('independent_authentication')}",
        "",
        "AUTHORITY",
        f"Root principal: {authority.get('root_principal')}",
        f"Structural binding: {authority.get('structural_binding')}",
        f"Independent crypto verification: {authority.get('independent_cryptographic_verification')}",
        "",
        "POLICY",
        f"Issuer: {policy.get('issuer')}",
        f"Signer: {policy.get('signer')}",
        f"Signer assessment: {policy.get('signature_assessment')}",
        f"Verdict: {policy.get('verdict')}",
        "",
        "BINDING",
        f"Status: {binding.get('status')}",
    ]
    for name, passed in (binding.get("checks") or {}).items():
        lines.append(f"- {name}: {_fmt(passed)}")
    lines.extend([
        "",
        "EXECUTION EVIDENCE",
        f"Status: {execution.get('status')}",
        f"Bound events: {len(execution.get('bound_events', []))}",
        f"Partially bound events: {len(execution.get('partially_bound_events', []))}",
        f"Unbound events: {len(execution.get('unbound_events', []))}",
        f"Malformed events: {execution.get('malformed_event_count', 0)}",
        f"Independent authentication: {execution.get('independent_authentication')}",
        f"External effect proven: {_fmt(execution.get('external_effect_proof'))}",
        f"Permit is execution: {_fmt(boundary.get('permit_is_execution'))}",
        "",
        "EVIDENCE BOUNDARY",
    ])
    for claim in boundary.get("claims", []):
        lines.append(f"- {claim}")
    return "\n".join(lines)


def render_text(report: dict[str, Any]) -> str:
    if str(report.get("schema", "")).startswith("agent-replay.aps-authority-reconstruction."):
        return _render_aps_text(report)
    lines: list[str] = []
    first = report.get("first_provable_divergence")
    coverage = report["expectation_coverage"]

    lines.append("AGENT REPLAY INCIDENT")
    lines.append(f"Evidence SHA-256: {report['input_sha256']}")
    lines.append(f"Canonical SHA-256: {report['canonical_sha256']}")
    if report.get("input_format"):
        lines.append(f"Input format: {report['input_format']}")
    if report.get("selected_trace_id"):
        lines.append(f"Selected trace: {report['selected_trace_id']}")
    if report.get("supplementary_evidence_bundle_sha256"):
        lines.append(
            "Supplementary evidence bundle SHA-256: "
            f"{report['supplementary_evidence_bundle_sha256']}"
        )
    lines.append(f"Events: {report['event_count']}")
    lines.append(
        "Expectation coverage: "
        f"{coverage['status']} "
        f"({coverage['events_with_expectations']}/{coverage['total_events']})"
    )
    lines.append(f"Reconstruction: {report['reconstruction_status']}")
    lines.append(f"Reproducibility: {report['reproducibility']}")
    lines.append(f"Confidence: {report['confidence']}")
    lines.append(f"Expectation scope: {report['expectation_scope']}")
    lines.append(f"Confidence scope: {report['confidence_scope']}")
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
        _append_evidence_gaps(lines, report)
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

    _append_evidence_gaps(lines, report)
    _append_trace(lines, report)
    return "\n".join(lines)
