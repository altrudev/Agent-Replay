import os

import pytest

import json
from pathlib import Path

from agent_replay.aps import reconstruct_aps_fixture
from agent_replay.reconstruct import reconstruct
from agent_replay_ddc.radial_mapping import incident_to_radial_spec
from agent_replay_ddc.radial_runner import analyze_incident


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


def test_authority_revocation_case_preserves_per_parent_semantics():
    incident = reconstruct(
        "examples/authority-revoked-before-execution/events.jsonl"
    )
    graph = incident_to_radial_spec(incident)

    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {(edge["src"], edge["dst"]): edge for edge in graph["edges"]}

    assert len(nodes) == 5
    assert len(edges) == 5

    assert nodes["approval_issued"]["authority"] == "approval-service"
    assert nodes["authority_revoked"]["authority"] == "authority-service"
    assert nodes["authority_revoked"]["mutable"] is True
    assert nodes["revocation_propagation"]["observable"] is False
    assert nodes["execution_attempt"]["authority"] == "payment-boundary"
    assert nodes["payment_executed"]["authority"] == "payment-api"
    assert nodes["payment_executed"]["consequence"] == 0.9
    assert nodes["payment_executed"]["reversible"] is False

    revocation = edges[("approval_issued", "authority_revoked")]
    assert revocation["relation"] == "revokes"
    assert revocation["independently_mutable"] is True
    assert revocation["shared_atomic_boundary"] is False
    assert revocation["time_gap"] == 0.2

    stale_approval = edges[("approval_issued", "execution_attempt")]
    assert stale_approval["relation"] == "authorizes"
    assert stale_approval["independently_mutable"] is True
    assert stale_approval["shared_atomic_boundary"] is False
    assert stale_approval["freshness_bound"] is False
    assert stale_approval["context_bound"] is True
    assert stale_approval["time_gap"] == 0.4

    current_authority = edges[("authority_revoked", "execution_attempt")]
    assert current_authority["relation"] == "depends_on"
    assert current_authority["independently_mutable"] is True
    assert current_authority["shared_atomic_boundary"] is False
    assert current_authority["time_gap"] == 0.2

    commit = edges[("execution_attempt", "payment_executed")]
    assert commit["relation"] == "commits"
    assert commit["independently_mutable"] is True
    assert commit["shared_atomic_boundary"] is False


@pytest.mark.skipif(
    not os.environ.get("DDC_RADIAL_ROOT"),
    reason="private DDC Radial checkout is not configured",
)
def test_authority_revocation_case_produces_radial_candidates():
    incident = reconstruct(
        "examples/authority-revoked-before-execution/events.jsonl"
    )
    result = analyze_incident(incident)
    prior_ids = {item["prior_id"] for item in result["hypotheses"]}

    assert result["authoritative"] is False
    assert result["disposition"] == "CANDIDATE_FINDINGS"
    assert "stale-authority" in prior_ids
    assert "toctou" in prior_ids


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


def test_malformed_per_parent_edge_hints_fail_closed():
    incident = {
        "schema": "agent-replay.incident.v2",
        "timeline": [
            {
                "event_id": "a",
                "actor": "a",
                "kind": "approval.issued",
                "evidence": {"source": "a"},
                "parent_ids": [],
            },
            {
                "event_id": "b",
                "actor": "b",
                "kind": "execution.attempted",
                "evidence": {
                    "source": "b",
                    "radial": {"edges": {"a": "not-an-object"}},
                },
                "parent_ids": ["a"],
            },
        ],
    }

    with pytest.raises(ValueError, match="radial.edges.a"):
        incident_to_radial_spec(incident)


def test_wrong_incident_schema_fails_closed():
    try:
        incident_to_radial_spec({"schema": "wrong"})
    except ValueError as exc:
        assert "does not support schema" in str(exc)
    else:
        raise AssertionError("wrong schema must fail closed")



def test_aps_reconstruction_maps_to_explicit_evidence_graph():
    fixture = json.loads(
        Path("tests/fixtures/aps-oracle-safety-check-v1/pass.json").read_text(
            encoding="utf-8"
        )
    )
    report = reconstruct_aps_fixture(fixture)
    graph = incident_to_radial_spec(report)

    assert [node["id"] for node in graph["nodes"]] == [
        "aps:intent",
        "aps:delegation",
        "aps:policy",
        "aps:execution",
    ]
    assert len(graph["edges"]) == 3
    execution = next(node for node in graph["nodes"] if node["id"] == "aps:execution")
    assert execution["observable"] is False
    policy_execution = next(
        edge for edge in graph["edges"]
        if edge["src"] == "aps:policy" and edge["dst"] == "aps:execution"
    )
    assert policy_execution["context_bound"] is False



def test_aps_broken_binding_weakens_radial_context_edges():
    fixture = json.loads(
        Path("tests/fixtures/aps-oracle-safety-check-v1/pass.json").read_text(
            encoding="utf-8"
        )
    )
    fixture["envelope"]["decision"]["delegation_ref"] = "sha256:wrong"
    report = reconstruct_aps_fixture(fixture)
    graph = incident_to_radial_spec(report)

    edges = {(edge["src"], edge["dst"]): edge for edge in graph["edges"]}
    assert edges[("aps:delegation", "aps:intent")]["context_bound"] is False
    assert edges[("aps:intent", "aps:policy")]["context_bound"] is False
