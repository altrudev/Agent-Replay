#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import agentrust_trace
from cryptography.exceptions import InvalidSignature

from agent_replay.trace import verify_trace_record


SYNTHETIC_TOOL_TRANSCRIPT = [
    {
        "tool": "example.lookup",
        "arguments": {"case_id": "spotlight-demo"},
        "result": {"status": "synthetic"},
    }
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_demo_json(value: object) -> bytes:
    # The synthetic fixture uses only JSON primitives for which this deterministic
    # encoding is stable. The demo does not claim that Replay verified this
    # transcript against the signed TRACE commitment.
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def synthetic_transcript_hash() -> str:
    return "sha256:" + sha256_bytes(canonical_demo_json(SYNTHETIC_TOOL_TRANSCRIPT))


def repo_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "UNKNOWN"


def installed_packages() -> dict[str, str]:
    packages: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if name:
            packages[name.lower().replace("_", "-")] = dist.version
    return dict(sorted(packages.items()))


def environment_fingerprint() -> dict:
    packages = installed_packages()
    package_bytes = canonical_demo_json(packages)
    return {
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "packages": packages,
        "packages_sha256": sha256_bytes(package_bytes),
    }


def base_record(iat: int) -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": iat,
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
        "tool_transcript": {
            "hash": synthetic_transcript_hash(),
            "call_count": len(SYNTHETIC_TOOL_TRANSCRIPT),
            "transcript_uri": "https://example.test/transcripts/spotlight-demo",
        },
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


def rejection_result(record_path: Path, key_path: Path) -> dict:
    rejected = {
        "status": "UNEXPECTED_ACCEPT",
        "reason": None,
        "record_sha256": sha256_bytes(record_path.read_bytes()),
    }
    try:
        verify_trace_record(record_path, key_path)
    except (InvalidSignature, ValueError) as exc:
        rejected["status"] = "REJECTED"
        rejected["reason"] = type(exc).__name__
    return rejected


def main() -> int:
    out_dir = Path("artifacts/agentrust-spotlight")
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_iat = int(time.time())
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(base_record(generated_iat), key)

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
    rejected = rejection_result(rejected_path, key_path)

    transcript_tampered = json.loads(valid_path.read_text(encoding="utf-8"))
    transcript_tampered["tool_transcript"]["hash"] = "sha256:" + "f" * 64
    transcript_tampered_path = out_dir / "adversarial-transcript-tampered.trace.json"
    transcript_tampered_path.write_text(
        json.dumps(transcript_tampered, indent=2, sort_keys=True), encoding="utf-8"
    )
    transcript_tamper_result = rejection_result(transcript_tampered_path, key_path)

    wrong_key = agentrust_trace.generate_key()
    wrong_key_path = out_dir / "adversarial-wrong-issuer.jwk"
    wrong_key_path.write_text(
        json.dumps(agentrust_trace.key_to_jwk(wrong_key), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    wrong_key_result = rejection_result(valid_path, wrong_key_path)

    env = environment_fingerprint()
    transcript_commitment = valid_summary.get("tool_transcript", {}).get("hash")

    manifest = {
        "demo": "AgenTrust spotlight",
        "repo_commit": repo_commit(),
        "generated_at_unix": generated_iat,
        "packages": {
            "agent-replay": importlib.metadata.version("agent-replay"),
            "agentrust-trace": importlib.metadata.version("agentrust-trace"),
        },
        "environment": env,
        "artifact_generation": {
            "fresh_key_each_run": True,
            "fresh_iat_each_run": True,
            "bit_for_bit_reproducible": False,
            "reason": (
                "TRACE freshness and ephemeral signing material are generated for each "
                "execution. The source revision and environment fingerprint are recorded "
                "so the run can be audited without claiming byte-identical artifacts."
            ),
        },
        "valid": valid_summary,
        "rejected": rejected,
        "adversarial_checks": {
            "signed_subject_tamper": rejected,
            "signed_transcript_hash_tamper": transcript_tamper_result,
            "wrong_caller_supplied_trusted_key": wrong_key_result,
        },
        "transcript_commitment": {
            "signed_hash": transcript_commitment,
            "synthetic_source_hash": synthetic_transcript_hash(),
            "synthetic_call_count": len(SYNTHETIC_TOOL_TRANSCRIPT),
            "source_is_demo_fixture": True,
            "transcript_supplied_to_trace_verifier": False,
            "incident_input_supplied_for_binding_check": False,
            "binding_evaluated": False,
        },
        "boundary": {
            "trace_record_verification": "VERIFIED only for the valid case",
            "transcript_commitment_presence": "VERIFIED_AS_SIGNED_FIELD",
            "transcript_to_incident_binding": "NOT_VERIFIED",
            "hardware_attestation": "NOT_INDEPENDENTLY_VERIFIED",
            "transparency_ledger_inclusion": "NOT_INDEPENDENTLY_VERIFIED",
            "post_execution_effect": "NOT_ESTABLISHED_BY_TRACE_VERIFICATION",
            "proof_horizon": (
                "The demo establishes TRACE record integrity within the verifier scope. "
                "It stops before transcript-to-incident equivalence, hardware provenance, "
                "transparency inclusion, delegated authority, or external-effect claims."
            ),
            "rule": (
                "A verified TRACE record is supplementary evidence. Agent Replay does not "
                "convert a signed tool_transcript.hash into proof that an incident input "
                "is that transcript or that a claimed external effect occurred."
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
    print(f"Python: {env['python']['version']} ({env['python']['implementation']})")
    print(f"Environment packages SHA-256: {env['packages_sha256']}")
    print("Fresh artifacts each run: YES (ephemeral key + current iat)")
    print()
    print("VALID TRACE")
    print(f"Status: {valid_summary['verification']['status']}")
    print(f"Record SHA-256: {valid_summary['record_sha256']}")
    print(f"Trusted key SHA-256: {valid_summary['trusted_key_sha256']}")
    print(f"Signed transcript commitment: {transcript_commitment}")
    print()
    print("REJECTED TRACE")
    print(f"Status: {rejected['status']}")
    print(f"Reason class: {rejected['reason']}")
    print(f"Record SHA-256: {rejected['record_sha256']}")
    print()
    print("ADVERSARIAL CHECKS")
    print(
        "Transcript-hash tamper: "
        f"{transcript_tamper_result['status']} ({transcript_tamper_result['reason']})"
    )
    print(
        "Wrong trusted key: "
        f"{wrong_key_result['status']} ({wrong_key_result['reason']})"
    )
    print()
    print("BOUNDARY")
    print("Signed transcript commitment present: VERIFIED_AS_SIGNED_FIELD")
    print("Transcript-to-incident binding: NOT_VERIFIED")
    print("Post-execution effect: NOT_ESTABLISHED_BY_TRACE_VERIFICATION")
    print(f"Manifest: {manifest_path}")

    all_rejections = (
        rejected["status"] == "REJECTED"
        and transcript_tamper_result["status"] == "REJECTED"
        and wrong_key_result["status"] == "REJECTED"
    )
    return 0 if all_rejections else 2


if __name__ == "__main__":
    raise SystemExit(main())
