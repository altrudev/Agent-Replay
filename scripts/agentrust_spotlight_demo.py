#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
import time
from pathlib import Path

import agentrust_trace
from cryptography.exceptions import InvalidSignature

from agent_replay.trace import verify_trace_record


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repo_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "UNKNOWN"


def base_record() -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "spiffe://example.test/agent/spotlight",
        "model": {"provider": "example", "model_id": "spotlight-demo"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "b" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 1,
            "digest": "sha256:" + "e" * 64,
        },
        "appraisal": {
            "status": "none",
            "verifier": "https://verifier.example.test",
        },
        "transparency": "https://registry.example.test/trace/spotlight-demo",
    }


def main() -> int:
    out_dir = Path("artifacts/agentrust-spotlight")
    out_dir.mkdir(parents=True, exist_ok=True)

    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(base_record(), key)

    valid_path = out_dir / "valid.trace.json"
    key_path = out_dir / "issuer-public.jwk"
    valid_path.write_text(json.dumps(signed, indent=2, sort_keys=True), encoding="utf-8")
    key_path.write_text(
        json.dumps(agentrust_trace.key_to_jwk(key), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    valid_summary = verify_trace_record(valid_path, key_path)

    tampered = json.loads(valid_path.read_text(encoding="utf-8"))
    tampered["subject"] = "spiffe://example.test/agent/tampered"
    rejected_path = out_dir / "rejected-tampered.trace.json"
    rejected_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8"
    )

    rejected = {
        "status": "UNEXPECTED_ACCEPT",
        "reason": None,
        "record_sha256": sha256_bytes(rejected_path.read_bytes()),
    }
    try:
        verify_trace_record(rejected_path, key_path)
    except (InvalidSignature, ValueError) as exc:
        rejected["status"] = "REJECTED"
        rejected["reason"] = type(exc).__name__

    manifest = {
        "demo": "AgenTrust spotlight",
        "repo_commit": repo_commit(),
        "packages": {
            "agent-replay": importlib.metadata.version("agent-replay"),
            "agentrust-trace": importlib.metadata.version("agentrust-trace"),
        },
        "valid": valid_summary,
        "rejected": rejected,
        "boundary": {
            "trace_record_verification": "VERIFIED only for the valid case",
            "transcript_to_incident_binding": "NOT_VERIFIED",
            "hardware_attestation": "NOT_INDEPENDENTLY_VERIFIED",
            "transparency_ledger_inclusion": "NOT_INDEPENDENTLY_VERIFIED",
            "post_execution_effect": "NOT_ESTABLISHED_BY_TRACE_VERIFICATION",
            "rule": (
                "A verified TRACE record is supplementary evidence. "
                "Agent Replay does not convert it into proof that an incident transcript "
                "matches tool_transcript.hash or that a claimed external effect occurred."
            ),
        },
    }

    manifest_path = out_dir / "spotlight-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    print("AGENTRUST SPOTLIGHT DEMO")
    print(f"Agent Replay: {manifest['packages']['agent-replay']}")
    print(f"agentrust-trace: {manifest['packages']['agentrust-trace']}")
    print(f"Commit: {manifest['repo_commit']}")
    print()
    print("VALID TRACE")
    print(f"Status: {valid_summary['verification']['status']}")
    print(f"Record SHA-256: {valid_summary['record_sha256']}")
    print(f"Trusted key SHA-256: {valid_summary['trusted_key_sha256']}")
    print()
    print("REJECTED TRACE")
    print(f"Status: {rejected['status']}")
    print(f"Reason class: {rejected['reason']}")
    print(f"Record SHA-256: {rejected['record_sha256']}")
    print()
    print("BOUNDARY")
    print("Transcript-to-incident binding: NOT_VERIFIED")
    print("Post-execution effect: NOT_ESTABLISHED_BY_TRACE_VERIFICATION")
    print(f"Manifest: {manifest_path}")

    return 0 if rejected["status"] == "REJECTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
