import json
from pathlib import Path

import jsonschema

from agent_replay.reconstruct import reconstruct


SCHEMA = json.loads(
    Path("schemas/incident-v2.schema.json").read_text(encoding="utf-8")
)


def test_refund_incident_conforms_to_published_schema():
    incident = reconstruct("examples/refund-750/events.jsonl")
    jsonschema.Draft202012Validator(SCHEMA).validate(incident)


def test_unassessed_incident_conforms_to_published_schema(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"event_id":"a","timestamp":"2026-01-01T00:00:00Z",'
        '"actor":"unknown","kind":"tool.call"}\n',
        encoding="utf-8",
    )

    incident = reconstruct(str(source))
    jsonschema.Draft202012Validator(SCHEMA).validate(incident)
    assert incident["timeline"][0]["status"] == "UNASSESSED"
