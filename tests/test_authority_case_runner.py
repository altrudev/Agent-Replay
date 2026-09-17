import json
import subprocess
import sys
from pathlib import Path


def test_authority_case_runner_owns_intermediate_artifacts(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    summary = tmp_path / "summary.json"

    subprocess.run(
        [
            sys.executable,
            str(repo / "tools" / "run_authority_case.py"),
            "--no-radial",
            "--no-share",
            "--summary-out",
            str(summary),
        ],
        cwd=repo,
        check=True,
    )

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["status"] == "PASS"
    assert result["production_integration"] is False
    assert result["alternate_route_retry_exercised"] is True
    assert result["primary_route_committed"] is False
    assert result["downstream_effect_count"] == 1
    assert result["revocation_delivery_acknowledgement_captured"] is False
    assert result["first_provable_divergence"] == "execution_decision"
    assert result["evidence_completeness"] == "INCOMPLETE"
    assert result["radial_reviewed"] is False
    assert result["public_share"] is None
