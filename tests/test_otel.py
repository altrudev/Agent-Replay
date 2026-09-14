import json
from pathlib import Path

import pytest

from agent_replay.otel import (
    OpenTelemetryFormatError,
    load_otlp_json,
    otlp_json_to_events,
    write_canonical_jsonl,
)
from agent_replay.reconstruct import reconstruct


def test_otlp_refund_fixture_normalizes_to_canonical_events(tmp_path: Path):
    events = load_otlp_json("examples/refund-750/otel.json")

    assert len(events) == 5
    assert events[0]["event_id"] == "span:001"
    assert events[1]["parent_ids"] == ["span:001"]
    assert events[1]["expected"]["policy_version"] == "v19"
    assert events[1]["observed"]["policy_version"] == "v17"
    assert events[2]["expected"]["refund_amount"] == 200
    assert events[2]["observed"]["refund_amount"] == 750
    assert events[3]["actor"] == "approval-gate"
    assert events[4]["actor"] == "payment-api"
    assert events[4]["evidence"]["trace_id"] == "trace-refund-750"

    target = tmp_path / "canonical.jsonl"
    write_canonical_jsonl("examples/refund-750/otel.json", target)
    report = reconstruct(str(target))

    assert report["event_count"] == 5
    assert report["expectation_coverage"]["status"] == "COMPLETE"
    assert report["first_provable_divergence"]["event_id"] == "span:019"
    assert report["confidence"] == "HIGH"


def test_generic_otel_without_expectations_does_not_invent_failure(tmp_path: Path):
    payload = {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "agent"}}
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "demo"},
                "spans": [{
                    "traceId": "t",
                    "spanId": "s",
                    "name": "tool.call",
                    "startTimeUnixNano": "1704067200000000000"
                }]
            }]
        }]
    }

    events = otlp_json_to_events(payload)
    target = tmp_path / "canonical.jsonl"
    target.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    report = reconstruct(str(target))

    assert report["divergences"] == []
    assert report["expectation_coverage"]["status"] == "NO_EXPECTATIONS"
    assert report["reproducibility"] == "NO_DIVERGENCE_FOUND"


def test_legacy_instrumentation_library_spans_are_supported():
    payload = {
        "resourceSpans": [{
            "instrumentationLibrarySpans": [{
                "instrumentationLibrary": {"name": "legacy", "version": "1"},
                "spans": [{
                    "traceId": "t",
                    "spanId": "s",
                    "name": "legacy.span",
                    "startTimeUnixNano": "1704067200000000000"
                }]
            }]
        }]
    }

    events = otlp_json_to_events(payload)
    assert events[0]["evidence"]["scope_name"] == "legacy"
    assert events[0]["evidence"]["scope_version"] == "1"


def test_empty_otlp_fails_closed():
    with pytest.raises(OpenTelemetryFormatError, match="no spans"):
        otlp_json_to_events({"resourceSpans": []})
