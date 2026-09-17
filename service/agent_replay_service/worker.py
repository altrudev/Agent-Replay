from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


class WorkerError(RuntimeError):
    pass


def run_replay_subprocess(*, evidence: bytes, timeout_seconds: float = 10.0, python_executable: str | None = None) -> dict[str, Any]:
    executable = python_executable or sys.executable
    with tempfile.TemporaryDirectory(prefix="agent-replay-") as tmp:
        path = Path(tmp) / "events.jsonl"
        path.write_bytes(evidence)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        command = [executable, "-m", "agent_replay_service.worker_cli", str(path)]
        try:
            proc = subprocess.run(
                command,
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise WorkerError("replay timed out") from exc
        if proc.returncode != 0:
            raise WorkerError("replay worker failed")
        try:
            return json.loads(proc.stdout.decode("utf-8"))
        except Exception as exc:
            raise WorkerError("replay worker returned invalid output") from exc
