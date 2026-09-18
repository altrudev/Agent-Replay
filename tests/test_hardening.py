from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_replay.normalize import EvidenceFormatError, normalize_jsonl, normalize_records
from agent_replay.reconstruct import reconstruct
from agent_replay.reproduce import compare_reconstruction


def _event(event_id: str, *, parent_ids=None):
    return {
        "event_id": event_id,
        "timestamp": "2026-09-17T00:00:00Z",
        "actor": "agent",
        "kind": "test.event",
        "parent_ids": parent_ids or [],
        "observed": {"ok": False},
        "expected": {"ok": True},
        "evidence": {},
    }


def test_max_events_is_enforced():
    with pytest.raises(EvidenceFormatError, match="max_events=1"):
        normalize_records([_event("a"), _event("b")], max_events=1)


def test_max_parents_is_enforced():
    records = [_event("a"), _event("b"), _event("c", parent_ids=["a", "b"])]
    with pytest.raises(EvidenceFormatError, match="max_parents=1"):
        normalize_records(records, max_parents=1)


def test_max_depth_is_enforced():
    records = [_event("a"), _event("b", parent_ids=["a"]), _event("c", parent_ids=["b"])]
    with pytest.raises(EvidenceFormatError, match="max_depth=1"):
        normalize_records(records, max_depth=1)


def test_max_bytes_is_enforced(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(_event("a")) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceFormatError, match="max_bytes=4"):
        normalize_jsonl(path, max_bytes=4)


def test_reproducibility_reports_reproduced(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(_event("a")) + "\n", encoding="utf-8")
    first = reconstruct(path)
    second = reconstruct(path)
    result = compare_reconstruction(first, second)
    assert result["status"] == "REPRODUCED"
    assert result["differences"] == []


def test_reproducibility_reports_drift():
    expected = {
        "canonical_sha256": "a" * 64,
        "event_count": 1,
        "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
        "first_provable_divergence": {"event_id": "a"},
        "causal_chain": [],
    }
    observed = dict(expected)
    observed["canonical_sha256"] = "b" * 64
    result = compare_reconstruction(expected, observed)
    assert result["status"] == "DRIFTED"
    assert result["differences"] == ["canonical_sha256"]



def test_reconstruct_rejects_oversized_input_before_reading_bytes(tmp_path: Path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(_event("a")) + "\n", encoding="utf-8")

    def explode(_self):
        raise AssertionError("read_bytes must not run for oversized input")

    monkeypatch.setattr(Path, "read_bytes", explode)
    with pytest.raises(EvidenceFormatError, match="max_bytes=1"):
        reconstruct(path, max_bytes=1)
