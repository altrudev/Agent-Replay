from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from agent_replay.html import PLACEHOLDER, render_html
from agent_replay.reconstruct import reconstruct

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = [
    ROOT / "examples" / "refund-750" / "events.jsonl",
    ROOT / "examples" / "authority-revoked-before-execution" / "events.jsonl",
]
AUTHORITATIVE = json.loads((ROOT / "schemas" / "authoritative-fields-v1.json").read_text(encoding="utf-8"))


def _embedded(page: str):
    match = re.search(
        r'<script type="application/json" id="incident-data">(.*?)</script>', page, re.DOTALL
    )
    assert match, "incident data block missing"
    return json.loads(match.group(1))


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "agent_replay.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
    )


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.parent.name)
def test_page_carries_authoritative_fields_unchanged(fixture: Path):
    """Platform Adapter Contract: the render surface must not alter or drop
    authoritative fields. The page embeds the core incident verbatim."""
    incident = reconstruct(fixture)
    embedded = _embedded(render_html(incident))
    for field in AUTHORITATIVE["incident-v2"]:
        assert embedded.get(field) == incident.get(field), field


def test_untrusted_values_cannot_break_out_of_the_data_block():
    hostile = "</script><script>alert(1)</script><!--     &amp;"
    page = render_html({"schema": "agent-replay.incident.v2", "timeline": [], "note": hostile})
    data_block = page.split('id="incident-data">', 1)[1].split("</script>", 1)[0]
    assert "<" not in data_block and ">" not in data_block and "&" not in data_block
    assert _embedded(page)["note"] == hostile


def test_page_makes_no_network_requests_and_never_uses_innerhtml():
    page = render_html(None)
    assert "default-src 'none'" in page
    assert not re.search(r'\b(src|href)\s*=\s*"https?://(?!github\.com/altrudev/Agent-Replay")', page)
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "fetch(", "XMLHttpRequest"):
        assert forbidden not in page, forbidden


def test_empty_viewer_has_no_embedded_incident():
    page = render_html(None)
    assert PLACEHOLDER not in page
    assert _embedded(page) is None


def test_cli_reconstruct_html_matches_json_output(tmp_path: Path):
    html_path = tmp_path / "report.html"
    proc = _cli("reconstruct", str(FIXTURES[0]), "--json", "--html", str(html_path))
    assert proc.returncode == 0, proc.stderr
    assert _embedded(html_path.read_text(encoding="utf-8")) == json.loads(proc.stdout)


def test_cli_view_renders_existing_incident(tmp_path: Path):
    incident_path = tmp_path / "incident.json"
    page_path = tmp_path / "view.html"
    assert _cli("reconstruct", str(FIXTURES[1]), "--json", "-o", str(incident_path)).returncode == 0
    proc = _cli("view", str(incident_path), "-o", str(page_path))
    assert proc.returncode == 0, proc.stderr
    assert _embedded(page_path.read_text(encoding="utf-8")) == json.loads(incident_path.read_text(encoding="utf-8"))


def test_demo_page_is_in_sync_with_core():
    spec = importlib.util.spec_from_file_location("build_demo", ROOT / "tools" / "build_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    committed = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert committed == module.build(), "docs/index.html is stale; run: python tools/build_demo.py"
