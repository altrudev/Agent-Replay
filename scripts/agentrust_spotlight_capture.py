#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".spotlight-venv"
CONSTRAINTS = ROOT / "docs" / "agentrust-spotlight-runtime-constraints-py314.txt"
TESTS = [
    "tests/test_trace.py",
    "tests/test_trace_real_verifier.py",
    "tests/test_agentrust_spotlight_demo.py",
]


def run(argv: list[str]) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, cwd=ROOT, check=True)


def main() -> int:
    if VENV.exists():
        shutil.rmtree(VENV)

    run([sys.executable, "-m", "venv", str(VENV)])
    python = str(VENV / "bin" / "python")

    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "-c",
            str(CONSTRAINTS),
            "-e",
            ".[trace,dev]",
        ]
    )
    run([python, "-m", "pytest", "-q", *TESTS])
    run([python, "scripts/agentrust_spotlight_demo.py"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
