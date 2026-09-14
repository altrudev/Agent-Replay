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

    # Actor labels are not automatically treated as authority domains.
    assert nodes["evt_023"]["authority"] == ""
    assert nodes["evt_024"]["authority"] == ""
    assert nodes["evt_025"]["authority"] == ""

    approval_edge = edges[("evt_023", "evt_024")]
    assert approval_edge["relation"] == "authorizes"
    assert approval_edge["independently_mutable"] is True
    assert approval_edge["shared_atomic_boundary"] is False
    assert approval_edge["context_bound"] is True
    assert approval_edge["time_gap"] == 0.2

    payment_edge = edges[("evt_024", "evt_025")]
    assert payment_edge["relation"] == "commits"
    assert payment_edge["independently_mutable"] is True
    assert payment_edge["shared_atomic_boundary"] is False
    assert payment_edge["context_bound"] is True
    assert payment_edge["time_gap"] == 0.2


def test_unknown_radial_properties_are_neutral_not_inferred():
    incident = {
        "schema": "agent-replay.incident.v2",
        "timeline": [
            {
                "event_id": "a",
                "actor": "actor-one",
                "kind": "policy.read",
                "evidence": {"source": "one"},
                "parent_ids": [],
                "status": "VALID",
            },
            {
                "event_id": "b",
                "actor": "actor-two",
                "kind": "payment.refund",
                "evidence": {"source": "two"},
                "parent_ids": ["a"],
                "status": "DIVERGENT",
            },
        ],
    }

    graph = incident_to_radial_spec(incident)
    nodes = {node["id"]: node for node in graph["nodes"]}
    edge = graph["edges"][0]

    assert nodes["a"]["representation"] == "agent-replay-canonical-v2"
    assert nodes["b"]["representation"] == "agent-replay-canonical-v2"

    # Different actor labels establish neither state independence nor
    # distinct authority domains.
    assert nodes["a"]["authority"] == ""
    assert nodes["b"]["authority"] == ""
    assert edge["independently_mutable"] is False

    assert edge["time_gap"] == 0.0
    assert edge["shared_atomic_boundary"] is True
    assert edge["freshness_bound"] is False
    assert edge["context_bound"] is True
    assert nodes["b"]["consequence"] == 0.0
    assert nodes["b"]["reversible"] is True


def test_explicit_authority_hint_is_preserved():
    incident = {
        "schema": "agent-replay.incident.v2",
        "timeline": [
            {
                "event_id": "a",
                "actor": "service-a",
                "kind": "approval.check",
                "evidence": {
                    "source": "one",
                    "radial": {"authority": "issuer-A"},
                },
                "parent_ids": [],
                "status": "VALID",
            }
        ],
    }

    graph = incident_to_radial_spec(incident)
    assert graph["nodes"][0]["authority"] == "issuer-A"


def test_wrong_incident_schema_fails_closed():
    try:
        incident_to_radial_spec({"schema": "wrong"})
    except ValueError as exc:
        assert "agent-replay.incident.v2" in str(exc)
    else:
        raise AssertionError("wrong schema must fail closed")
