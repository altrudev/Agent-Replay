"""Regenerate the public demo page at docs/index.html.

The demo is the visual report for examples/refund-750, produced through the
normal reconstruction path so it can never drift from what the CLI emits.
GitHub Pages can serve it directly from the docs/ folder.

    python tools/build_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_replay.html import render_html  # noqa: E402
from agent_replay.reconstruct import reconstruct  # noqa: E402

DEMO_INPUT = "examples/refund-750/events.jsonl"
DEMO_OUTPUT = ROOT / "docs" / "index.html"


def build() -> str:
    incident = reconstruct(ROOT / DEMO_INPUT)
    incident["input_format"] = "canonical-jsonl"
    return render_html(incident)


def main() -> None:
    DEMO_OUTPUT.write_text(build(), encoding="utf-8")
    print(str(DEMO_OUTPUT.relative_to(ROOT)))


if __name__ == "__main__":
    main()
