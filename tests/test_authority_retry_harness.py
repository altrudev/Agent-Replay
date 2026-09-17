import json
import subprocess
import sys
from pathlib import Path

from agent_replay.reconstruct import reconstruct


def test_authority_retry_harness_exercises_alternate_route(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "tools" / "authority_retry_harness.py"
    events = tmp_path / "events.jsonl"
    result = tmp_path / "harness-result.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--events",
            str(events),
            "--result",
            str(result),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    harness = json.loads(result.read_text(encoding="utf-8"))
    assert harness["alternate_route_retry_exercised"] is True
    assert harness["primary_route_committed"] is False
    assert harness["downstream_effect_count"] == 1
    assert harness["revocation_delivery_acknowledgement_captured"] is False
    assert harness["production_integration"] is False
    assert harness["events_sha256"]
    assert "alternate_route_retry_exercised" in completed.stdout

    incident = reconstruct(str(events))
    assert incident["first_provable_divergence"]["event_id"] == "execution_decision"
    assert incident["evidence_completeness"] == "INCOMPLETE"

    divergent_ids = {item["event_id"] for item in incident["divergences"]}
    assert "alternate_route_retry" in divergent_ids
    assert "payment_executed" in divergent_ids

    gaps = {item["event_id"] for item in incident["evidence_gaps"]}
    assert "revocation_propagation" in gaps
