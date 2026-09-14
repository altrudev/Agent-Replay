from agent_replay.reconstruct import reconstruct


def test_first_divergence():
    report = reconstruct("examples/refund-750/events.jsonl")
    first = report["first_provable_divergence"]

    assert first["event_id"] == "evt_019"
    assert first["mismatches"][0]["observed"] == "v17"
    assert first["mismatches"][0]["expected"] == "v19"
