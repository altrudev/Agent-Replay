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
    assert events[0]["event_id"] == "span:trace-refund-750:001"
    assert events[1]["parent_ids"] == ["span:trace-refund-750:001"]
    assert events[1]["expected"]["policy_version"] == "v19"
    assert events[1]["observed"]["policy_version"] == "v17"
    assert events[2]["expected"]["refund_amount"] == 200
    assert events[2]["observed"]["refund_amount"] == 750
    assert events[3]["actor"] == "approval-gate"
    assert events[4]["actor"] == "payment-api"
    assert events[4]["evidence"]["trace_id"] == "trace-refund-750"
    assert events[4]["evidence"]["radial"]["relation"] == "commits"
    assert events[4]["evidence"]["otel_start_time_unix_nano"] == "1789416269000000000"

    target = tmp_path / "canonical.jsonl"
    write_canonical_jsonl("examples/refund-750/otel.json", target)
    report = reconstruct(str(target))

    assert report["event_count"] == 5
    assert report["expectation_coverage"]["status"] == "COMPLETE"
    assert (
        report["first_provable_divergence"]["event_id"]
        == "span:trace-refund-750:019"
    )
    assert report["confidence"] == "HIGH"
    assert report["reproducibility"] == "NOT_TESTED"


def test_parent_span_is_not_causal_without_explicit_hint():
    payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": "t",
                        "spanId": "p",
                        "name": "parent",
                        "startTimeUnixNano": "1704067200000000000"
                    },
                    {
                        "traceId": "t",
                        "spanId": "c",
                        "parentSpanId": "p",
                        "name": "child",
                        "startTimeUnixNano": "1704067200000001000"
                    }
                ]
            }]
        }]
    }

    events = otlp_json_to_events(payload)
    child = next(item for item in events if item["event_id"].endswith(":c"))

    assert child["parent_ids"] == []
    assert child["evidence"]["otel_parent_event_id"] == "span:t:p"


def test_explicit_causal_parent_is_preserved():
    payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": "t",
                        "spanId": "p",
                        "name": "parent",
                        "startTimeUnixNano": "1704067200000000000"
                    },
                    {
                        "traceId": "t",
                        "spanId": "c",
                        "parentSpanId": "p",
                        "name": "child",
                        "startTimeUnixNano": "1704067200000001000",
                        "attributes": [{
                            "key": "agent.replay.causal_parent",
                            "value": {"boolValue": True}
                        }]
                    }
                ]
            }]
        }]
    }

    events = otlp_json_to_events(payload)
    child = next(item for item in events if item["event_id"].endswith(":c"))

    assert child["parent_ids"] == ["span:t:p"]


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
    assert report["timeline"][0]["status"] == "UNASSESSED"
    assert report["reconstruction_status"] == "NO_DIVERGENCE_ESTABLISHED"
    assert report["reproducibility"] == "NOT_TESTED"


def test_partial_trace_preserves_external_parent_without_false_edge():
    payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [{
                    "traceId": "t",
                    "spanId": "child",
                    "parentSpanId": "not-exported",
                    "name": "tool.call",
                    "startTimeUnixNano": "1704067200000000000"
                }]
            }]
        }]
    }

    events = otlp_json_to_events(payload)
    assert events[0]["parent_ids"] == []
    assert events[0]["evidence"]["external_parent_span_id"] == "not-exported"


def test_multiple_traces_require_explicit_selection():
    payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": "trace-a",
                        "spanId": "same",
                        "name": "a",
                        "startTimeUnixNano": "1704067200000000000"
                    },
                    {
                        "traceId": "trace-b",
                        "spanId": "same",
                        "name": "b",
                        "startTimeUnixNano": "1704067201000000000"
                    }
                ]
            }]
        }]
    }

    with pytest.raises(OpenTelemetryFormatError, match="multiple traces"):
        otlp_json_to_events(payload)

    selected = otlp_json_to_events(payload, trace_id="trace-b")
    assert len(selected) == 1
    assert selected[0]["event_id"] == "span:trace-b:same"


def test_nanosecond_ordering_survives_microsecond_display_precision(tmp_path: Path):
    payload = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": "t",
                        "spanId": "later",
                        "name": "later",
                        "startTimeUnixNano": "1704067200000000900",
                        "attributes": [
                            {"key": "agent.replay.expected.x", "value": {"intValue": "1"}},
                            {"key": "agent.replay.observed.x", "value": {"intValue": "2"}}
                        ]
                    },
                    {
                        "traceId": "t",
                        "spanId": "earlier",
                        "name": "earlier",
                        "startTimeUnixNano": "1704067200000000100",
                        "attributes": [
                            {"key": "agent.replay.expected.x", "value": {"intValue": "1"}},
                            {"key": "agent.replay.observed.x", "value": {"intValue": "2"}}
                        ]
                    }
                ]
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

    assert report["first_provable_divergence"]["event_id"] == "span:t:earlier"


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
