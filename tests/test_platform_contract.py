from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return json.loads((ROOT / "schemas" / "authoritative-fields-v1.json").read_text(encoding="utf-8"))


def _project(value: dict, fields: list[str]) -> dict:
    return {field: value.get(field) for field in fields}


def test_authoritative_manifest_is_versioned_and_known():
    manifest = _manifest()
    assert manifest["schema"] == "agent-replay.authoritative-fields.v1"
    assert "incident-v2" in manifest
    assert "aps-authority-reconstruction-v2" in manifest


def test_incident_manifest_tracks_required_authoritative_schema_fields():
    manifest = _manifest()["incident-v2"]
    schema = json.loads((ROOT / "schemas" / "incident-v2.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]).issubset(set(manifest))


def test_aps_manifest_tracks_required_authoritative_schema_fields():
    manifest = _manifest()["aps-authority-reconstruction-v2"]
    schema = json.loads((ROOT / "schemas" / "aps-authority-reconstruction-v2.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]).issubset(set(manifest))


def test_adapter_projection_detects_authoritative_drift():
    fields = ["schema", "reconstruction_status", "reproducibility"]
    core = {"schema": "agent-replay.incident.v2", "reconstruction_status": "DIVERGENCE_RECONSTRUCTED", "reproducibility": "REPRODUCED", "ui": "core"}
    adapter = dict(core, ui="vscode")
    assert _project(core, fields) == _project(adapter, fields)
    adapter["reproducibility"] = "NOT_TESTED"
    assert _project(core, fields) != _project(adapter, fields)
