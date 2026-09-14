from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


class OpenTelemetryFormatError(ValueError):
    pass


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in (
        "stringValue",
        "boolValue",
        "intValue",
        "doubleValue",
        "bytesValue",
    ):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", [])
        return [_otel_value(item) for item in values]
    if "kvlistValue" in value:
        return {
            item["key"]: _otel_value(item.get("value"))
            for item in value["kvlistValue"].get("values", [])
            if isinstance(item, dict) and "key" in item
        }
    return value


def _attributes(items: Any) -> dict[str, Any]:
    if not isinstance(items, list):
        return {}
    out: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not isinstance(key, str):
            continue
        out[key] = _otel_value(item.get("value"))
    return out


def _timestamp_from_unix_nano(value: Any) -> str:
    try:
        nanos = int(value)
    except (TypeError, ValueError) as exc:
        raise OpenTelemetryFormatError(
            f"invalid startTimeUnixNano: {value!r}"
        ) from exc
    seconds, remainder = divmod(nanos, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(
        microsecond=remainder // 1000
    )
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _split_expected_observed(
    attrs: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected: dict[str, Any] = {}
    observed: dict[str, Any] = {}
    expected_prefix = "agent.replay.expected."
    observed_prefix = "agent.replay.observed."

    for key, value in attrs.items():
        if key.startswith(expected_prefix):
            expected[key[len(expected_prefix):]] = value
        elif key.startswith(observed_prefix):
            observed[key[len(observed_prefix):]] = value
    return expected, observed


def _resource_actor(
    resource_attrs: dict[str, Any],
    span_attrs: dict[str, Any],
) -> str:
    for key in (
        "agent.name",
        "gen_ai.agent.name",
        "service.name",
    ):
        value = span_attrs.get(key)
        if isinstance(value, str) and value:
            return value
        value = resource_attrs.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def otlp_json_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    resource_spans = payload.get("resourceSpans")
    if not isinstance(resource_spans, list):
        raise OpenTelemetryFormatError(
            "OTLP JSON must contain resourceSpans[]"
        )

    events: list[dict[str, Any]] = []
    seen: set[str] = set()

    for resource_block in resource_spans:
        if not isinstance(resource_block, dict):
            continue
        resource = resource_block.get("resource") or {}
        resource_attrs = _attributes(resource.get("attributes"))

        scope_spans = resource_block.get("scopeSpans")
        if not isinstance(scope_spans, list):
            continue

        for scope_block in scope_spans:
            if not isinstance(scope_block, dict):
                continue
            spans = scope_block.get("spans")
            if not isinstance(spans, list):
                continue

            for span in spans:
                if not isinstance(span, dict):
                    continue

                span_id = span.get("spanId")
                if not isinstance(span_id, str) or not span_id:
                    raise OpenTelemetryFormatError("spanId is required")
                event_id = f"span:{span_id}"
                if event_id in seen:
                    raise OpenTelemetryFormatError(
                        f"duplicate spanId: {span_id}"
                    )
                seen.add(event_id)

                span_attrs = _attributes(span.get("attributes"))
                expected, observed = _split_expected_observed(span_attrs)

                parent_span_id = span.get("parentSpanId")
                parent_ids = (
                    [f"span:{parent_span_id}"]
                    if isinstance(parent_span_id, str) and parent_span_id
                    else []
                )

                trace_id = span.get("traceId")
                name = span.get("name")
                kind = (
                    span_attrs.get("agent.replay.kind")
                    if isinstance(span_attrs.get("agent.replay.kind"), str)
                    else name
                )
                if not isinstance(kind, str) or not kind:
                    kind = "otel.span"

                evidence = {
                    "source": "opentelemetry",
                    "trace_id": trace_id,
                    "span_id": span_id,
                }

                scope = scope_block.get("scope")
                if isinstance(scope, dict):
                    if isinstance(scope.get("name"), str):
                        evidence["scope_name"] = scope["name"]
                    if isinstance(scope.get("version"), str):
                        evidence["scope_version"] = scope["version"]

                events.append(
                    {
                        "event_id": event_id,
                        "timestamp": _timestamp_from_unix_nano(
                            span.get("startTimeUnixNano")
                        ),
                        "actor": _resource_actor(resource_attrs, span_attrs),
                        "kind": kind,
                        "parent_ids": parent_ids,
                        "observed": observed,
                        "expected": expected,
                        "evidence": evidence,
                    }
                )

    return events


def load_otlp_json(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OpenTelemetryFormatError(
            f"invalid OTLP JSON: {exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise OpenTelemetryFormatError("OTLP JSON root must be an object")
    return otlp_json_to_events(payload)


def write_canonical_jsonl(
    input_path: str | Path,
    output_path: str | Path,
) -> Path:
    events = load_otlp_json(input_path)
    target = Path(output_path)
    target.write_text(
        "".join(
            json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
            for event in events
        ),
        encoding="utf-8",
    )
    return target
