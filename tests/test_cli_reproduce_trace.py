from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_replay import cli
from agent_replay.reconstruct import reconstruct


def _event() -> dict:
    return {
        "event_id": "a",
        "timestamp": "2026-09-17T00:00:00Z",
        "actor": "agent",
        "kind": "test.event",
        "observed": {"ok": False},
        "expected": {"ok": True},
        "evidence": {},
    }


def _trace_summary() -> dict:
    return {
        "record_sha256": "b" * 64,
        "trusted_key_sha256": "c" * 64,
        "verification": {"status": "VERIFIED"},
    }


def _write_trace_backed_incident(tmp_path: Path) -> tuple[Path, Path, dict]:
    evidence = tmp_path / "events.jsonl"
    evidence.write_text(json.dumps(_event()) + "\n", encoding="utf-8")
    incident = reconstruct(evidence)
    trace = _trace_summary()
    incident["trace_evidence"] = trace
    incident["supplementary_evidence_bundle_sha256"] = cli._supplementary_bundle_sha256(
        incident, trace
    )
    incident_path = tmp_path / "incident.json"
    incident_path.write_text(json.dumps(incident), encoding="utf-8")
    return incident_path, evidence, trace


def test_reproduce_cli_marks_missing_trace_scope_incomplete(tmp_path: Path, monkeypatch):
    incident, evidence, _ = _write_trace_backed_incident(tmp_path)
    output = tmp_path / "result.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-replay", "reproduce", str(incident), str(evidence), "-o", str(output)],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 3
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "INCOMPLETE"
    assert result["supplementary_evidence"] == "NOT_REPRODUCED"


def test_reproduce_cli_replays_supplied_trace_scope(tmp_path: Path, monkeypatch):
    incident, evidence, trace = _write_trace_backed_incident(tmp_path)
    record = tmp_path / "record.json"
    key = tmp_path / "issuer.pem"
    record.write_text("{}", encoding="utf-8")
    key.write_text("test-key", encoding="utf-8")
    output = tmp_path / "result.json"

    monkeypatch.setattr(cli, "verify_trace_record", lambda *_: trace)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-replay",
            "reproduce",
            str(incident),
            str(evidence),
            "--trace-record",
            str(record),
            "--trace-key",
            str(key),
            "-o",
            str(output),
        ],
    )

    cli.main()

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "REPRODUCED"
    assert result["evidence_scope"] == "CORE_PLUS_TRACE"
    assert result["supplementary_evidence"] == "REPRODUCED"


def test_reproduce_cli_requires_trace_record_and_key_together(tmp_path: Path, monkeypatch):
    incident, evidence, _ = _write_trace_backed_incident(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-replay",
            "reproduce",
            str(incident),
            str(evidence),
            "--trace-record",
            str(tmp_path / "record.json"),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
