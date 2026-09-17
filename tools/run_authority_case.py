#!/usr/bin/env python3
"""One-command deterministic runner for the authority-revocation case.

This removes manual sequencing between harness generation, reconstruction,
optional DDC Radial review, and secure export. It fails fast if any prerequisite
or expected output is missing.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], *, stdin: Path | None = None, stdout: Path | None = None) -> None:
    print("+", " ".join(cmd))
    fin = stdin.open("rb") if stdin else None
    fout = stdout.open("wb") if stdout else None
    try:
        subprocess.run(cmd, check=True, stdin=fin, stdout=fout)
    finally:
        if fin:
            fin.close()
        if fout:
            fout.close()


def require(path: Path, label: str) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"FAIL: missing {label}: {path}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="/tmp/agent-replay-authority-case")
    p.add_argument("--with-radial", action="store_true")
    p.add_argument("--share", action="store_true")
    p.add_argument("--agent-replay-commit")
    args = p.parse_args()

    repo = Path(__file__).resolve().parents[1]
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    harness = repo / "tools" / "authority_retry_harness.py"
    require(harness, "harness source")

    events = out / "events.jsonl"
    harness_result = out / "harness-result.json"
    incident = out / "incident.json"
    radial = out / "radial.internal.json"
    public = out / "public-share.json"

    run([sys.executable, str(harness), "--events", str(events), "--result", str(harness_result)])
    require(events, "harness events")
    require(harness_result, "harness result")

    run([sys.executable, "-m", "agent_replay.cli", "reconstruct", str(events), "--json", "-o", str(incident)])
    require(incident, "reconstruction")

    if args.with_radial or args.share:
        radial_root = os.environ.get("DDC_RADIAL_ROOT")
        if not radial_root:
            raise SystemExit("FAIL: DDC_RADIAL_ROOT is required for --with-radial/--share")
        exe = Path(sys.executable).parent / "agent-replay-ddc-radial"
        if not exe.is_file():
            raise SystemExit(f"FAIL: missing radial adapter executable: {exe}")
        run([str(exe), "--json"], stdin=incident, stdout=radial)
        require(radial, "Radial review")

    if args.share:
        commit = args.agent_replay_commit
        if not commit:
            try:
                commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            except Exception as exc:
                raise SystemExit(f"FAIL: could not resolve Agent Replay commit: {exc}")
        run([
            sys.executable, "-m", "agent_replay.cli", "export-share", str(incident),
            "--radial", str(radial), "--agent-replay-commit", commit, "-o", str(public),
        ])
        require(public, "public share bundle")

    h = json.loads(harness_result.read_text())
    i = json.loads(incident.read_text())
    summary = {
        "status": "PASS",
        "out": str(out),
        "production_integration": h.get("production_integration"),
        "alternate_route_retry_exercised": h.get("alternate_route_retry_exercised"),
        "primary_route_committed": h.get("primary_route_committed"),
        "downstream_effect_count": h.get("downstream_effect_count"),
        "revocation_delivery_acknowledgement_captured": h.get("revocation_delivery_acknowledgement_captured"),
        "first_provable_divergence": (i.get("first_provable_divergence") or {}).get("event_id"),
        "evidence_completeness": i.get("evidence_completeness"),
        "public_share": str(public) if args.share else None,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
