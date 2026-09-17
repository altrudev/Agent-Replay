#!/usr/bin/env python3
"""Single-command deterministic runner for the authority-revocation case.

The runner owns the whole workflow: environment selection, harness generation,
reconstruction, optional DDC Radial review, secure export, validation, and the
final summary. Intermediate artifacts live in a unique private temporary run
directory so stale files cannot satisfy a later step by accident.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _ensure_repo_venv(repo: Path) -> None:
    """Re-exec inside the repository venv when it exists.

    This removes the requirement for the operator to remember `. .venv/bin/activate`.
    """
    venv_python = repo / ".venv" / "bin" / "python3"
    if not venv_python.is_file():
        venv_python = repo / ".venv" / "bin" / "python"
    if not venv_python.is_file():
        raise SystemExit(
            "FAIL: repository virtual environment is missing. Expected .venv/bin/python3"
        )
    current = Path(sys.executable).resolve()
    expected = venv_python.resolve()
    if current != expected:
        os.execv(str(expected), [str(expected), str(Path(__file__).resolve()), *sys.argv[1:]])


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    stdin: Path | None = None,
    stdout: Path | None = None,
) -> None:
    print("+", " ".join(cmd), flush=True)
    fin = stdin.open("rb") if stdin else None
    fout = stdout.open("wb") if stdout else None
    try:
        subprocess.run(
            cmd,
            check=True,
            cwd=cwd,
            env=env,
            stdin=fin,
            stdout=fout,
        )
    finally:
        if fin:
            fin.close()
        if fout:
            fout.close()


def _require(path: Path, label: str) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"FAIL: {label} was not produced: {path}")


def _load_json(path: Path, label: str) -> dict:
    _require(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"FAIL: {label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"FAIL: {label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_radial_root(repo: Path, requested: str | None) -> Path:
    candidates: list[Path] = []
    if requested:
        candidates.append(Path(requested).expanduser())
    if os.environ.get("DDC_RADIAL_ROOT"):
        candidates.append(Path(os.environ["DDC_RADIAL_ROOT"]).expanduser())
    candidates.extend([Path.home() / "src" / "ddc", repo.parent / "ddc"])

    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        if (candidate / "src" / "radial_frequency_v10.py").is_file():
            return candidate
    raise SystemExit(
        "FAIL: DDC Radial root not found. Looked at --ddc-root, DDC_RADIAL_ROOT, ~/src/ddc, and sibling ../ddc"
    )


def _git_head(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, stderr=subprocess.STDOUT
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"FAIL: could not resolve Agent Replay commit: {exc.output.strip()}") from exc


def _validate_harness(h: dict) -> None:
    expected = {
        "production_integration": False,
        "alternate_route_retry_exercised": True,
        "primary_route_committed": False,
        "downstream_effect_count": 1,
        "revocation_delivery_acknowledgement_captured": False,
    }
    mismatches = {k: (expected[k], h.get(k)) for k in expected if h.get(k) != expected[k]}
    if mismatches:
        raise SystemExit(f"FAIL: harness acceptance mismatch: {mismatches}")


def _validate_incident(i: dict) -> None:
    first = (i.get("first_provable_divergence") or {}).get("event_id")
    if first != "execution_decision":
        raise SystemExit(f"FAIL: unexpected first provable divergence: {first!r}")
    if i.get("evidence_completeness") != "INCOMPLETE":
        raise SystemExit(
            f"FAIL: evidence gap was not preserved: completeness={i.get('evidence_completeness')!r}"
        )
    gap_ids = {
        str(item.get("event_id"))
        for item in i.get("evidence_gaps") or []
        if isinstance(item, dict)
    }
    if "revocation_propagation" not in gap_ids:
        raise SystemExit("FAIL: revocation propagation evidence gap disappeared")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Run the complete authority-revocation evidence workflow in one command."
    )
    p.add_argument(
        "--public-out",
        default="authority-case-public-share.json",
        help="final sanitized share bundle path (default: ./authority-case-public-share.json)",
    )
    p.add_argument("--summary-out", help="optional final run summary JSON path")
    p.add_argument("--ddc-root", help="DDC checkout; auto-detected when omitted")
    p.add_argument("--no-radial", action="store_true", help="skip DDC Radial review")
    p.add_argument("--no-share", action="store_true", help="skip sanitized public bundle")
    p.add_argument("--keep-internal", action="store_true", help="preserve internal run directory for debugging")
    p.add_argument("--agent-replay-commit", help="override commit bound into the public bundle")
    args = p.parse_args()

    repo = _repo_root()
    _ensure_repo_venv(repo)

    harness = repo / "tools" / "authority_retry_harness.py"
    _require(harness, "harness source")

    radial_enabled = not args.no_radial
    share_enabled = not args.no_share
    if share_enabled and not radial_enabled:
        raise SystemExit("FAIL: --no-radial cannot be combined with sharing; the public bundle requires the review artifact")

    run_dir = Path(tempfile.mkdtemp(prefix="agent-replay-authority-case-"))
    events = run_dir / "events.jsonl"
    harness_result = run_dir / "harness-result.json"
    incident = run_dir / "incident.json"
    radial = run_dir / "radial.internal.json"
    public_internal = run_dir / "public-share.json"

    env = os.environ.copy()
    try:
        _run(
            [sys.executable, str(harness), "--events", str(events), "--result", str(harness_result)],
            cwd=repo,
            env=env,
        )
        _require(events, "harness events")
        h = _load_json(harness_result, "harness result")
        _validate_harness(h)

        _run(
            [sys.executable, "-m", "agent_replay.cli", "reconstruct", str(events), "--json", "-o", str(incident)],
            cwd=repo,
            env=env,
        )
        i = _load_json(incident, "reconstruction")
        _validate_incident(i)

        radial_review: dict | None = None
        if radial_enabled:
            radial_root = _resolve_radial_root(repo, args.ddc_root)
            env["DDC_RADIAL_ROOT"] = str(radial_root)
            radial_exe = Path(sys.executable).parent / "agent-replay-ddc-radial"
            _require(radial_exe, "Radial adapter executable")
            _run([str(radial_exe), "--json"], cwd=repo, env=env, stdin=incident, stdout=radial)
            radial_review = _load_json(radial, "Radial review")
            if radial_review.get("authoritative") is True:
                raise SystemExit("FAIL: Radial review unexpectedly marked itself authoritative")

        public_path: Path | None = None
        commit = args.agent_replay_commit or _git_head(repo)
        if share_enabled:
            _run(
                [
                    sys.executable,
                    "-m",
                    "agent_replay.cli",
                    "export-share",
                    str(incident),
                    "--radial",
                    str(radial),
                    "--agent-replay-commit",
                    commit,
                    "-o",
                    str(public_internal),
                ],
                cwd=repo,
                env=env,
            )
            public_bundle = _load_json(public_internal, "public share bundle")
            policy = public_bundle.get("sharing_policy") or {}
            if policy.get("raw_source_included") is not False or policy.get("raw_evidence_included") is not False:
                raise SystemExit("FAIL: public bundle disclosure policy is unsafe")
            if policy.get("proprietary_engine_details_included") is not False:
                raise SystemExit("FAIL: proprietary engine details crossed the share boundary")
            public_path = Path(args.public_out).expanduser().resolve()
            public_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(public_internal, public_path)

        summary = {
            "status": "PASS",
            "agent_replay_commit": commit,
            "harness_source_sha256": h.get("harness_source_sha256"),
            "events_sha256": h.get("events_sha256") or _sha256(events),
            "production_integration": h.get("production_integration"),
            "alternate_route_retry_exercised": h.get("alternate_route_retry_exercised"),
            "primary_route_committed": h.get("primary_route_committed"),
            "downstream_effect_count": h.get("downstream_effect_count"),
            "revocation_delivery_acknowledgement_captured": h.get("revocation_delivery_acknowledgement_captured"),
            "first_provable_divergence": (i.get("first_provable_divergence") or {}).get("event_id"),
            "evidence_completeness": i.get("evidence_completeness"),
            "radial_reviewed": radial_enabled,
            "radial_candidate_count": radial_review.get("candidate_count") if radial_review else None,
            "public_share": str(public_path) if public_path else None,
        }
        text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        print(text, end="")
        if args.summary_out:
            summary_path = Path(args.summary_out).expanduser().resolve()
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(text, encoding="utf-8")
    finally:
        if args.keep_internal:
            print(f"Internal run directory retained: {run_dir}", file=sys.stderr)
        else:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
