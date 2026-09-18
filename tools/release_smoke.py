#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.6.0"


def run(argv: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"release smoke failed: {' '.join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="agent-replay-release-smoke-") as td:
        temp = Path(td)
        wheels = temp / "wheels"
        wheels.mkdir()

        run([
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheels),
        ])
        wheel_files = list(wheels.glob("agent_replay-*.whl"))
        if len(wheel_files) != 1:
            raise SystemExit(f"expected one core wheel, found {wheel_files}")

        env_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(env_dir)
        python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        agent_replay = env_dir / ("Scripts/agent-replay.exe" if os.name == "nt" else "bin/agent-replay")
        run([str(python), "-m", "pip", "install", "--no-index", str(wheel_files[0])])

        version = run([str(agent_replay), "--version"]).stdout.strip()
        if version != f"agent-replay {EXPECTED_VERSION}":
            raise SystemExit(f"unexpected installed version: {version}")

        doctor = json.loads(run([str(agent_replay), "doctor"]).stdout)
        if doctor.get("core") != "READY" or doctor.get("version") != EXPECTED_VERSION:
            raise SystemExit(f"doctor did not report installed core READY: {doctor}")

        incident = temp / "incident.json"
        run([
            str(agent_replay),
            "reconstruct",
            "examples/refund-750/events.jsonl",
            "--json",
            "-o",
            str(incident),
        ])
        incident_doc = json.loads(incident.read_text(encoding="utf-8"))
        if incident_doc.get("reconstruction_status") != "DIVERGENCE_RECONSTRUCTED":
            raise SystemExit("installed-wheel reconstruction did not reproduce expected example")

        public = temp / "public-share.json"
        run([str(agent_replay), "export-share", str(incident), "-o", str(public)])
        if not public.is_file() or not json.loads(public.read_text(encoding="utf-8")):
            raise SystemExit("installed-wheel public-share export missing or invalid")

        aps_incident = temp / "aps-incident.json"
        run([
            str(agent_replay),
            "reconstruct",
            "tests/fixtures/aps-oracle-safety-check-v1/pass.json",
            "--format",
            "aps",
            "--json",
            "-o",
            str(aps_incident),
        ])
        aps_doc = json.loads(aps_incident.read_text(encoding="utf-8"))
        if aps_doc.get("execution_status") != "NO_EXECUTION_EVIDENCE":
            raise SystemExit(
                "installed-wheel APS reconstruction crossed execution boundary"
            )

        aps_public = temp / "aps-public-share.json"
        run([
            str(agent_replay),
            "export-share",
            str(aps_incident),
            "-o",
            str(aps_public),
        ])
        aps_share = json.loads(aps_public.read_text(encoding="utf-8"))
        if aps_share.get("incident", {}).get("schema") != "agent-replay.public-aps-share.v1":
            raise SystemExit("installed-wheel APS safe-share export missing or invalid")

    print("AGENT REPLAY RELEASE SMOKE PASS")


if __name__ == "__main__":
    main()
