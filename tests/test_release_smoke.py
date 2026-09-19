from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_clean_wheel_release_smoke() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "release_smoke.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, (
        "clean-wheel release smoke failed\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )
    assert "AGENT REPLAY RELEASE SMOKE PASS" in proc.stdout
