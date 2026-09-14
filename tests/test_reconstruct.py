from pathlib import Path

from agent_replay.reconstruct import reconstruct
from agent_replay.report import render_text


def test_first_divergence():
    report = reconstruct("examples/refund-750/events.jsonl")
    first = report["first_provable_divergence"]

    assert report["schema"] == "agent-replay.incident.v2"
    assert first["event_id"] == "evt_019"
    assert first["mismatches"][0]["observed"] == "v17"
    assert first["mismatches"][0]["expected"] == "v19"


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


def test_text_report_contains_core_findings():
    text = render_text(reconstruct("examples/refund-750/events.jsonl"))

    assert "FIRST PROVABLE DIVERGENCE" in text
    assert "policy_version: expected=v19 observed=v17" in text
    assert "refund-agent: PRIMARY" in text
