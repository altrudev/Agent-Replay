from agent_replay.reconstruct import reconstruct
from agent_replay_ddc.radial_mapping import incident_to_radial_spec


def test_refund_incident_maps_to_radial_graph():
    incident = reconstruct("examples/refund-750/events.jsonl")
    graph = incident_to_radial_spec(incident)

    assert len(graph["nodes"]) == 5
    assert len(graph["edges"]) == 3

    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {(edge["src"], edge["dst"]): edge for edge in graph["edges"]}

    assert "policy" in nodes["evt_019"]["dimensions"]
    assert "authority" in nodes["evt_024"]["dimensions"]
    assert nodes["evt_025"]["reversible"] is False
    assert nodes["evt_025"]["consequence"] == 0.9

    approval_edge = edges[("evt_023", "evt_024")]
    assert approval_edge["relation"] == "authorizes"
    assert approval_edge["independently_mutable"] is True
    assert approval_edge["shared_atomic_boundary"] is False

    payment_edge = edges[("evt_024", "evt_025")]
    assert payment_edge["relation"] == "commits"
    assert payment_edge["independently_mutable"] is True


def test_wrong_incident_schema_fails_closed():
    try:
        incident_to_radial_spec({"schema": "wrong"})
    except ValueError as exc:
        assert "agent-replay.incident.v2" in str(exc)
    else:
        raise AssertionError("wrong schema must fail closed")
