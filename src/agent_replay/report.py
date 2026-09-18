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
    source = report.get("source", {})
    tested = source.get("adapter_tested_against", {})
    provenance = source.get("input_provenance", {})
    conformance = source.get("external_conformance", {})
    identity = report.get("identity", {})
    authority = report.get("authority", {})
    policy = report.get("policy", {})
    binding = report.get("binding", {})
    execution = report.get("execution", {})
    boundary = report.get("evidence_boundary", {})
    lines = [
        "AGENT REPLAY APS AUTHORITY RECONSTRUCTION",
        f"Fixture label: {source.get('fixture')}",
        f"Input SHA-256: {provenance.get('sha256')}",
        f"Input provenance: {provenance.get('provenance_status')}",
        f"Input provenance verification: {provenance.get('verification')}",
        f"Adapter tested against APS revision: {tested.get('revision')}",
        f"External APS conformance: {conformance.get('outcome')}",
        "",
        "IDENTITY",
        f"Claimed actor: {identity.get('claimed_actor')}",
        f"Intent signer claim: {identity.get('intent_signer')}",
        f"Intent authentication: {identity.get('intent_authentication')}",
        "",
        "AUTHORITY",
        f"Root principal: {authority.get('root_principal')}",
        f"Evidence status: {authority.get('evidence_status')}",
        f"External disposition: {authority.get('external_conformance_disposition')}",
        f"Replay verification: {authority.get('replay_verification')}",
    ]
    for index, link in enumerate(authority.get("delegation_path", []), 1):
        lines.append(f"- link {index}: {link.get('issuer')} -> {link.get('subject')} ({link.get('delegation_id')})")
    lines.extend([
        "",
        "BINDING",
        f"Overall: {binding.get('status')}",
        f"Action ref matched: {_fmt((binding.get('action_ref') or {}).get('matched'))}",
        f"Receipt link matched: {_fmt((binding.get('receipt_link') or {}).get('matched'))}",
        f"Delegation ref matched: {_fmt((binding.get('delegation_ref') or {}).get('matched'))}",
        f"Delegation chain continuous: {_fmt(binding.get('delegation_chain_continuity'))}",
        "",
        "POLICY",
        f"Issuer: {policy.get('issuer')}",
        f"Signer claim: {policy.get('signer')}",
        f"Authentication: {policy.get('authentication')}",
        f"Verdict: {policy.get('verdict')}",
        "",
        "EXECUTION",
        f"Status: {execution.get('status')}",
        f"Evidence events: {execution.get('evidence_count')}",
        f"Action-bound events: {execution.get('action_bound_count')}",
        f"Actor-bound events: {execution.get('actor_bound_count')}",
        f"Cryptographic authentication: {execution.get('cryptographic_authentication')}",
        f"Permit is execution: {_fmt(boundary.get('permit_is_execution'))}",
        "",
        "EVIDENCE BOUNDARY",
    ])
    for statement in boundary.get("can_establish", []):
        lines.append(f"- CAN: {statement}")
    for statement in boundary.get("cannot_establish", []):
        lines.append(f"- CANNOT: {statement}")
    return "\n".join(lines)

def render_text(report: dict[str, Any]) -> str:
    if report.get("schema") == "agent-replay.aps-authority-reconstruction.v1":
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
