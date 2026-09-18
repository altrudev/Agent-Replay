from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from agent_replay.aps import reconstruct_aps_fixture
from agent_replay.reconstruct import reconstruct
from agent_replay.share import build_share_bundle, sanitize_aps_reconstruction, sanitize_incident, sanitize_radial


def _schema(name: str) -> dict:
    return json.loads((Path("schemas") / name).read_text(encoding="utf-8"))


def test_all_public_schemas_are_valid_json_schema():
    for name in (
        "public-share-v1.schema.json",
        "public-radial-review-v1.schema.json",
        "share-bundle-v1.schema.json",
        "aps-authority-reconstruction-v1.schema.json",
        "public-aps-authority-v1.schema.json",
    ):
        jsonschema.Draft202012Validator.check_schema(_schema(name))


def test_sanitized_incident_conforms_to_public_schema():
    incident = reconstruct("examples/refund-750/events.jsonl")
    public = sanitize_incident(incident)
    jsonschema.Draft202012Validator(
        _schema("public-share-v1.schema.json")
    ).validate(public)


def test_sanitized_radial_conforms_to_public_schema():
    public = sanitize_radial({
        "engine_source": {"sha256": "c" * 64},
        "authoritative": False,
        "disposition": "NO_CANDIDATES",
        "examined_nodes": 5,
        "examined_edges": 4,
        "mapping_provenance": {"EXPLICIT": 3, "INFERRED": 2, "DEFAULT": 7},
        "hypotheses": [],
    })
    jsonschema.Draft202012Validator(
        _schema("public-radial-review-v1.schema.json")
    ).validate(public)


def test_share_bundle_has_expected_contract_identity():
    incident = reconstruct("examples/refund-750/events.jsonl")
    bundle = build_share_bundle(incident, agent_replay_commit="abc123")
    assert bundle["schema"] == "agent-replay.share-bundle.v1"
    assert bundle["incident"]["schema"] == "agent-replay.public-share.v1"
    assert len(bundle["bundle_sha256"]) == 64



def test_aps_reconstruction_conforms_to_schema():
    source = Path("tests/fixtures/aps/oracle-safety-check-v1/pass.json")
    raw = source.read_bytes()
    document = json.loads(raw)
    report = reconstruct_aps_fixture(document)
    jsonschema.Draft202012Validator(
        _schema("aps-authority-reconstruction-v1.schema.json")
    ).validate(report)


def test_sanitized_aps_conforms_to_public_schema_and_share_bundle_schema():
    source = Path("tests/fixtures/aps/oracle-safety-check-v1/pass.json")
    report = reconstruct_aps_fixture(json.loads(source.read_text(encoding="utf-8")))
    public = sanitize_aps_reconstruction(report)
    jsonschema.Draft202012Validator(
        _schema("public-aps-authority-v1.schema.json")
    ).validate(public)
    bundle = build_share_bundle(report)
    jsonschema.Draft202012Validator(
        _schema("share-bundle-v1.schema.json")
    ).validate(bundle)
