#!/usr/bin/env python3
from __future__ import annotations

import configparser
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.6.0"


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
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

        # Build through the project's declared PEP 517 backend directly.
        # This keeps the smoke test fully offline and avoids importing the
        # distro pip network stack merely to build a local wheel.
        run([
            sys.executable,
            "-c",
            (
                "from setuptools import build_meta;"
                "import sys;"
                "print(build_meta.build_wheel(sys.argv[1]))"
            ),
            str(wheels),
        ])
        wheel_files = list(wheels.glob("agent_replay-*.whl"))
        if len(wheel_files) != 1:
            raise SystemExit(f"expected one core wheel, found {wheel_files}")

        env_dir = temp / "venv"
        venv.EnvBuilder(with_pip=False, clear=True).create(env_dir)
        python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

        purelib = Path(
            run(
                [
                    str(python),
                    "-c",
                    "import sysconfig; print(sysconfig.get_paths()['purelib'])",
                ],
                cwd=temp,
            ).stdout.strip()
        )

        wheel_file = wheel_files[0]
        with zipfile.ZipFile(wheel_file) as wheel:
            names = wheel.namelist()
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts:
                    raise SystemExit(f"unsafe wheel member: {name}")
            if any(".data/" in name for name in names):
                raise SystemExit("release smoke only supports purelib wheels without .data relocation")

            entry_points = [
                name for name in names if name.endswith(".dist-info/entry_points.txt")
            ]
            if len(entry_points) != 1:
                raise SystemExit(f"expected one entry_points.txt, found {entry_points}")
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(wheel.read(entry_points[0]).decode("utf-8"))
            if parser.get("console_scripts", "agent-replay", fallback="") != "agent_replay.cli:main":
                raise SystemExit("wheel console entry point is missing or incorrect")

            wheel.extractall(purelib)

        installed_path = run(
            [
                str(python),
                "-c",
                "import agent_replay; print(agent_replay.__file__)",
            ],
            cwd=temp,
        ).stdout.strip()
        if str(purelib) not in installed_path:
            raise SystemExit(f"installed package resolved outside clean venv: {installed_path}")

        cli_code = (
            "import sys;"
            "from agent_replay.cli import main;"
            "sys.argv=['agent-replay',*sys.argv[1:]];"
            "raise SystemExit(main())"
        )

        def cli(*args: str) -> subprocess.CompletedProcess[str]:
            return run([str(python), "-c", cli_code, *args], cwd=temp)

        version = cli("--version").stdout.strip()
        if version != f"agent-replay {EXPECTED_VERSION}":
            raise SystemExit(f"unexpected installed version: {version}")

        doctor = json.loads(cli("doctor").stdout)
        if doctor.get("core") != "READY" or doctor.get("version") != EXPECTED_VERSION:
            raise SystemExit(f"doctor did not report installed core READY: {doctor}")

        incident = temp / "incident.json"
        cli(
            "reconstruct",
            str(ROOT / "examples" / "refund-750" / "events.jsonl"),
            "--json",
            "-o",
            str(incident),
        )
        incident_doc = json.loads(incident.read_text(encoding="utf-8"))
        if incident_doc.get("reconstruction_status") != "DIVERGENCE_RECONSTRUCTED":
            raise SystemExit("installed-wheel reconstruction did not reproduce expected example")

        public = temp / "public-share.json"
        cli("export-share", str(incident), "-o", str(public))
        if not public.is_file() or not json.loads(public.read_text(encoding="utf-8")):
            raise SystemExit("installed-wheel public-share export missing or invalid")

        aps_incident = temp / "aps-incident.json"
        cli(
            "reconstruct",
            str(
                ROOT
                / "tests"
                / "fixtures"
                / "aps-oracle-safety-check-v1"
                / "pass.json"
            ),
            "--format",
            "aps",
            "--json",
            "-o",
            str(aps_incident),
        )
        aps_doc = json.loads(aps_incident.read_text(encoding="utf-8"))
        if aps_doc.get("execution_status") != "NO_EXECUTION_EVIDENCE":
            raise SystemExit(
                "installed-wheel APS reconstruction crossed execution boundary"
            )

        aps_public = temp / "aps-public-share.json"
        cli(
            "export-share",
            str(aps_incident),
            "-o",
            str(aps_public),
        )
        aps_share = json.loads(aps_public.read_text(encoding="utf-8"))
        if aps_share.get("incident", {}).get("schema") != "agent-replay.public-aps-share.v1":
            raise SystemExit("installed-wheel APS safe-share export missing or invalid")

    print("AGENT REPLAY RELEASE SMOKE PASS")


if __name__ == "__main__":
    main()
