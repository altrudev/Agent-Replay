from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TraceDependencyError(RuntimeError):
    pass


class TraceEvidenceError(ValueError):
    pass


def _trace_api():
    try:
        from agentrust_trace import validate_json, verify_record
    except ImportError as exc:
        raise TraceDependencyError(
            "TRACE support is optional. Install with: pip install 'agent-replay[trace]'"
        ) from exc
    return validate_json, verify_record


def _load_json_object(path: str | Path, label: str) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TraceEvidenceError(f"{label} is not valid JSON: {source}") from exc
    if not isinstance(value, dict):
        raise TraceEvidenceError(f"{label} must be a JSON object: {source}")
    return value


def _load_trusted_key(path: str | Path):
    source = Path(path)
    if source.suffix.lower() in {".json", ".jwk"}:
        return _load_json_object(source, "trusted TRACE key")

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise TraceDependencyError(
            "PEM TRACE keys require the optional TRACE dependency. "
            "Install with: pip install 'agent-replay[trace]'"
        ) from exc

    try:
        return load_pem_public_key(source.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise TraceEvidenceError(f"trusted TRACE key is not a valid PEM public key: {source}") from exc


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    model = record.get("model") if isinstance(record.get("model"), dict) else {}
    runtime = record.get("runtime") if isinstance(record.get("runtime"), dict) else {}
    policy = record.get("policy") if isinstance(record.get("policy"), dict) else {}
    transcript = (
        record.get("tool_transcript")
        if isinstance(record.get("tool_transcript"), dict)
        else {}
    )
    appraisal = (
        record.get("appraisal") if isinstance(record.get("appraisal"), dict) else {}
    )

    return {
        "format": "TRACE",
        "eat_profile": record.get("eat_profile"),
        "iat": record.get("iat"),
        "subject": record.get("subject"),
        "model": {
            "provider": model.get("provider"),
            "model_id": model.get("model_id"),
        },
        "runtime": {
            "platform": runtime.get("platform"),
            "measurement": runtime.get("measurement"),
        },
        "policy": {
            "bundle_hash": policy.get("bundle_hash"),
            "enforcement_mode": policy.get("enforcement_mode"),
        },
        "data_class": record.get("data_class"),
        "tool_transcript": {
            "hash": transcript.get("hash"),
            "call_count": transcript.get("call_count"),
            "transcript_uri": transcript.get("transcript_uri"),
        },
        "appraisal": {
            "status": appraisal.get("status"),
            "verifier": appraisal.get("verifier"),
        },
        "transparency": record.get("transparency"),
        "verification": {
            "status": "VERIFIED",
            "trusted_key_source": "caller-supplied",
            "scope": (
                "TRACE schema/profile/signature/freshness verification using an "
                "externally supplied trusted key. Agent Replay does not independently "
                "verify hardware attestation, transparency-ledger inclusion, or that "
                "the incident input is the transcript committed by tool_transcript.hash."
            ),
        },
    }


def verify_trace_record(
    record_path: str | Path,
    trusted_key_path: str | Path,
) -> dict[str, Any]:
    """Verify a standalone TRACE Trust Record without trusting its embedded key."""
    record = _load_json_object(record_path, "TRACE record")
    if "trace" in record and "signature" in record:
        raise TraceEvidenceError(
            "cMCP RuntimeClaim envelopes are not accepted by this adapter yet; "
            "provide a standalone TRACE Trust Record."
        )

    validate_json, verify_record = _trace_api()
    trusted_key = _load_trusted_key(trusted_key_path)

    validate_json(record)
    verify_record(record, public_key_or_jwk=trusted_key)
    return _summary(record)


def render_trace_summary(summary: dict[str, Any]) -> str:
    verification = summary["verification"]
    model = summary.get("model", {})
    runtime = summary.get("runtime", {})
    policy = summary.get("policy", {})
    transcript = summary.get("tool_transcript", {})

    lines = [
        "TRACE EVIDENCE",
        f"Verification: {verification['status']}",
        f"Subject: {summary.get('subject')}",
        f"Model: {model.get('provider')}/{model.get('model_id')}",
        f"Runtime: {runtime.get('platform')}",
        f"Policy mode: {policy.get('enforcement_mode')}",
    ]
    if transcript.get("hash"):
        lines.append(f"Tool transcript hash: {transcript['hash']}")
    lines.append(f"Scope: {verification['scope']}")
    return "\n".join(lines)
