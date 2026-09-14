from pathlib import Path

import pytest

from agent_replay.normalize import EvidenceFormatError
from agent_replay.reconstruct import reconstruct
from agent_replay.report import render_text


def test_first_divergence():
    report = reconstruct("examples/refund-750/events.jsonl")
    first = report["first_provable_divergence"]

    assert report["schema"] == "agent-replay.incident.v2"
    assert len(report["input_sha256"]) == 64
    assert len(report["canonical_sha256"]) == 64
    assert first["event_id"] == "evt_019"
    assert first["mismatches"][0]["observed"] == "v17"
    assert first["mismatches"][0]["expected"] == "v19"


def test_full_timeline_preserves_valid_and_divergent_events():
    report = reconstruct("examples/refund-750/events.jsonl")

    assert [item["event_id"] for item in report["timeline"]] == [
        "evt_001",
        "evt_019",
        "evt_023",
        "evt_024",
        "evt_025",
    ]
    assert report["timeline"][0]["status"] == "VALID"
    assert report["timeline"][1]["status"] == "DIVERGENT"


def test_explicit_causal_chain_and_attribution():
    report = reconstruct("examples/refund-750/events.jsonl")
    relationships = {
        item["event_id"]: item["relationship"]
        for item in report["causal_chain"]
    }
    roles = {
        item["actor"]: item["role"]
        for item in report["attribution"]
    }

    assert relationships["evt_019"] == "ROOT_DIVERGENCE"
    assert relationships["evt_023"] == "EXPLICITLY_DOWNSTREAM"
    assert relationships["evt_024"] == "EXPLICITLY_DOWNSTREAM"
    assert relationships["evt_025"] == "EXPLICITLY_DOWNSTREAM"
    assert roles["refund-agent"] == "PRIMARY"
    assert roles["approval-gate"] == "CONTRIBUTING"
    assert roles["payment-api"] == "CONTRIBUTING"
    assert report["confidence"] == "HIGH"
    assert report["attribution_scope"].startswith("EVIDENCE_LABELS_ONLY")


def test_no_invented_causality_without_parent_links(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"a","timestamp":"2026-01-01T00:00:00Z","actor":"one",'
        '"kind":"first","expected":{"x":1},"observed":{"x":2}}\n'
        '{"event_id":"b","timestamp":"2026-01-01T00:00:01Z","actor":"two",'
        '"kind":"second","expected":{"y":1},"observed":{"y":2}}\n',
        encoding="utf-8",
    )

    report = reconstruct(str(source))
    second = report["causal_chain"][1]

    assert second["relationship"] == "TEMPORALLY_DOWNSTREAM"
    assert report["confidence"] == "MEDIUM"


def test_timestamps_are_normalized_before_ordering(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"later","timestamp":"2026-01-01T01:00:00+00:00","actor":"a",'
        '"kind":"later","expected":{"x":1},"observed":{"x":2}}\n'
        '{"event_id":"earlier","timestamp":"2025-12-31T18:00:00-07:00","actor":"a",'
        '"kind":"earlier","expected":{"x":1},"observed":{"x":2}}\n',
        encoding="utf-8",
    )

    report = reconstruct(str(source))
    assert [item["event_id"] for item in report["timeline"]] == ["earlier", "later"]
    assert report["timeline"][0]["timestamp"].endswith("Z")


def test_unknown_parent_fails_closed(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"a","timestamp":"2026-01-01T00:00:00Z","actor":"a",'
        '"kind":"x","parent_ids":["missing"]}\n',
        encoding="utf-8",
    )
    with pytest.raises(EvidenceFormatError, match="unknown parent_id"):
        reconstruct(str(source))


def test_future_parent_fails_closed(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"parent","timestamp":"2026-01-01T00:00:02Z","actor":"a","kind":"x"}\n'
        '{"event_id":"child","timestamp":"2026-01-01T00:00:01Z","actor":"a",'
        '"kind":"y","parent_ids":["parent"]}\n',
        encoding="utf-8",
    )
    with pytest.raises(EvidenceFormatError, match="occurs after child"):
        reconstruct(str(source))


def test_parent_cycle_fails_closed(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"a","timestamp":"2026-01-01T00:00:00Z","actor":"a",'
        '"kind":"x","parent_ids":["b"]}\n'
        '{"event_id":"b","timestamp":"2026-01-01T00:00:00Z","actor":"b",'
        '"kind":"y","parent_ids":["a"]}\n',
        encoding="utf-8",
    )
    with pytest.raises(EvidenceFormatError, match="cycle"):
        reconstruct(str(source))


def test_text_report_contains_core_findings():
    text = render_text(reconstruct("examples/refund-750/events.jsonl"))

    assert "TIMELINE" in text
    assert "Canonical SHA-256:" in text
    assert "FIRST PROVABLE DIVERGENCE" in text
    assert "policy_version: expected=v19 observed=v17" in text
    assert "refund-agent: PRIMARY" in text
    assert "EVIDENCE_LABELS_ONLY" in text
