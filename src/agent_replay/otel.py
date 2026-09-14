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
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return value["intValue"]
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return value["doubleValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        array = value["arrayValue"]
        values = array.get("values", []) if isinstance(array, dict) else []
        return [_otel_value(item) for item in values]
    if "kvlistValue" in value:
        kvlist = value["kvlistValue"]
        values = kvlist.get("values", []) if isinstance(kvlist, dict) else []
        return {
            item["key"]: _otel_value(item.get("value"))
            for item in values
            if isinstance(item, dict) and isinstance(item.get("key"), str)
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


def _radial_hints(attrs: dict[str, Any]) -> dict[str, Any]:
    prefix = "agent.replay.radial."
    allowed = {
        "authority",
        "mutable",
        "representation",
        "consequence",
        "reversible",
        "time_gap",
        "independently_mutable",
        "shared_atomic_boundary",
        "freshness_bound",
        "context_bound",
    }
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        if not key.startswith(prefix):
            continue
        name = key[len(prefix):]
        if name in allowed:
            out[name] = value
    return out


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


def _scope_blocks(resource_block: dict[str, Any]) -> list[dict[str, Any]]:
    current = resource_block.get("scopeSpans")
    if isinstance(current, list):
        return [item for item in current if isinstance(item, dict)]

    legacy = resource_block.get("instrumentationLibrarySpans")
    if isinstance(legacy, list):
        return [item for item in legacy if isinstance(item, dict)]

    return []


def _scope_metadata(scope_block: dict[str, Any]) -> dict[str, str]:
    scope = scope_block.get("scope")
    if not isinstance(scope, dict):
        scope = scope_block.get("instrumentationLibrary")
    if not isinstance(scope, dict):
        return {}

    out: dict[str, str] = {}
    if isinstance(scope.get("name"), str):
        out["scope_name"] = scope["name"]
    if isinstance(scope.get("version"), str):
        out["scope_version"] = scope["version"]
    return out


def _event_id(trace_id: str, span_id: str) -> str:
    return f"span:{trace_id}:{span_id}"


def otlp_json_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    resource_spans = payload.get("resourceSpans")
    if not isinstance(resource_spans, list):
        raise OpenTelemetryFormatError(
            "OTLP JSON must contain resourceSpans[]"
        )

    flattened: list[tuple[dict[str, Any], dict[str, Any], dict[str, str]]] = []
    available: set[tuple[str, str]] = set()

    for resource_block in resource_spans:
        if not isinstance(resource_block, dict):
            continue
        resource = resource_block.get("resource") or {}
        resource_attrs = (
            _attributes(resource.get("attributes"))
            if isinstance(resource, dict)
            else {}
        )

        for scope_block in _scope_blocks(resource_block):
            spans = scope_block.get("spans")
            if not isinstance(spans, list):
                continue
            scope_meta = _scope_metadata(scope_block)

            for span in spans:
                if not isinstance(span, dict):
                    continue
                trace_id = span.get("traceId")
                span_id = span.get("spanId")
                if not isinstance(trace_id, str) or not trace_id:
                    raise OpenTelemetryFormatError("traceId is required")
                if not isinstance(span_id, str) or not span_id:
                    raise OpenTelemetryFormatError("spanId is required")
                key = (trace_id, span_id)
                if key in available:
                    raise OpenTelemetryFormatError(
                        f"duplicate span identity: traceId={trace_id} spanId={span_id}"
                    )
                available.add(key)
                flattened.append((span, resource_attrs, scope_meta))

    if not flattened:
        raise OpenTelemetryFormatError("OTLP JSON contained no spans")

    events: list[dict[str, Any]] = []

    for span, resource_attrs, scope_meta in flattened:
        trace_id = span["traceId"]
        span_id = span["spanId"]
        span_attrs = _attributes(span.get("attributes"))
        expected, observed = _split_expected_observed(span_attrs)

        parent_span_id = span.get("parentSpanId")
        parent_ids: list[str] = []

        evidence: dict[str, Any] = {
            "source": "opentelemetry",
            "trace_id": trace_id,
            "span_id": span_id,
        }
        evidence.update(scope_meta)

        radial = _radial_hints(span_attrs)
        if radial:
            evidence["radial"] = radial

        if isinstance(parent_span_id, str) and parent_span_id:
            if (trace_id, parent_span_id) in available:
                parent_ids.append(_event_id(trace_id, parent_span_id))
            else:
                evidence["external_parent_span_id"] = parent_span_id

        name = span.get("name")
        kind_override = span_attrs.get("agent.replay.kind")
        kind = (
            kind_override
            if isinstance(kind_override, str) and kind_override
            else name
        )
        if not isinstance(kind, str) or not kind:
            kind = "otel.span"

        status = span.get("status")
        if isinstance(status, dict):
            if "code" in status:
                evidence["otel_status_code"] = status["code"]
            if isinstance(status.get("message"), str):
                evidence["otel_status_message"] = status["message"]

        events.append(
            {
                "event_id": _event_id(trace_id, span_id),
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
