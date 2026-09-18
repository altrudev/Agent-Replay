from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .normalize import DEFAULT_MAX_BYTES, DEFAULT_MAX_EVENTS


class OpenTelemetryFormatError(ValueError):
    pass


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        raw = value["boolValue"]
        if not isinstance(raw, bool):
            raise OpenTelemetryFormatError("boolValue must be a JSON boolean")
        return raw
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
        if key in out and key.startswith("agent.replay."):
            raise OpenTelemetryFormatError(
                f"duplicate Agent Replay attribute: {key}"
            )
        out[key] = _otel_value(item.get("value"))
    return out


def _timestamp_from_unix_nano(value: Any) -> str:
    try:
        nanos = int(value)
    except (TypeError, ValueError) as exc:
        raise OpenTelemetryFormatError(
            f"invalid startTimeUnixNano: {value!r}"
        ) from exc
    try:
        seconds, remainder = divmod(nanos, 1_000_000_000)
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(
            microsecond=remainder // 1000
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise OpenTelemetryFormatError(
            f"startTimeUnixNano is out of range: {value!r}"
        ) from exc
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
        "authority", "mutable", "representation", "consequence", "reversible",
        "time_gap", "independently_mutable", "shared_atomic_boundary",
        "freshness_bound", "context_bound", "relation", "observable",
    }
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        if not key.startswith(prefix):
            continue
        name = key[len(prefix):]
        if name in allowed:
            out[name] = value
    return out


def _resource_actor(resource_attrs: dict[str, Any], span_attrs: dict[str, Any]) -> str:
    for key in ("agent.name", "gen_ai.agent.name", "service.name"):
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


def _flatten_otlp(
    payload: dict[str, Any],
    *,
    max_events: int,
) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, str]]]:
    resource_spans = payload.get("resourceSpans")
    if not isinstance(resource_spans, list):
        raise OpenTelemetryFormatError("OTLP JSON must contain resourceSpans[]")

    flattened: list[tuple[dict[str, Any], dict[str, Any], dict[str, str]]] = []
    seen: set[tuple[str, str]] = set()

    for resource_block in resource_spans:
        if not isinstance(resource_block, dict):
            continue
        resource = resource_block.get("resource") or {}
        resource_attrs = _attributes(resource.get("attributes")) if isinstance(resource, dict) else {}
        for scope_block in _scope_blocks(resource_block):
            spans = scope_block.get("spans")
            if not isinstance(spans, list):
                continue
            scope_meta = _scope_metadata(scope_block)
            for span in spans:
                if not isinstance(span, dict):
                    continue
                if len(flattened) >= max_events:
                    raise OpenTelemetryFormatError(
                        f"OTLP span count exceeds max_events={max_events}"
                    )
                trace_id = span.get("traceId")
                span_id = span.get("spanId")
                if not isinstance(trace_id, str) or not trace_id:
                    raise OpenTelemetryFormatError("traceId is required")
                if not isinstance(span_id, str) or not span_id:
                    raise OpenTelemetryFormatError("spanId is required")
                identity = (trace_id, span_id)
                if identity in seen:
                    raise OpenTelemetryFormatError(
                        f"duplicate span identity: traceId={trace_id} spanId={span_id}"
                    )
                seen.add(identity)
                flattened.append((span, resource_attrs, scope_meta))

    if not flattened:
        raise OpenTelemetryFormatError("OTLP JSON contained no spans")
    return flattened


def otlp_json_to_events(
    payload: dict[str, Any], *, trace_id: str | None = None,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> list[dict[str, Any]]:
    flattened = _flatten_otlp(payload, max_events=max_events)
    trace_ids = sorted({span["traceId"] for span, _, _ in flattened})
    if trace_id is None:
        if len(trace_ids) > 1:
            raise OpenTelemetryFormatError(
                "OTLP JSON contains multiple traces; select one trace_id explicitly"
            )
        selected_trace_id = trace_ids[0]
    else:
        selected_trace_id = trace_id
        if selected_trace_id not in trace_ids:
            raise OpenTelemetryFormatError(f"requested trace_id not found: {selected_trace_id}")

    selected = [item for item in flattened if item[0]["traceId"] == selected_trace_id]
    available = {(span["traceId"], span["spanId"]) for span, _, _ in selected}
    events: list[dict[str, Any]] = []

    for span, resource_attrs, scope_meta in selected:
        current_trace_id = span["traceId"]
        span_id = span["spanId"]
        span_attrs = _attributes(span.get("attributes"))
        expected, observed = _split_expected_observed(span_attrs)
        raw_start = span.get("startTimeUnixNano")
        parent_span_id = span.get("parentSpanId")
        parent_ids: list[str] = []
        evidence: dict[str, Any] = {
            "source": "opentelemetry",
            "trace_id": current_trace_id,
            "span_id": span_id,
            "otel_start_time_unix_nano": str(raw_start),
        }
        evidence.update(scope_meta)
        radial = _radial_hints(span_attrs)
        if radial:
            evidence["radial"] = radial

        causal_parent = span_attrs.get("agent.replay.causal_parent", False)
        if not isinstance(causal_parent, bool):
            raise OpenTelemetryFormatError("agent.replay.causal_parent must be a boolean")

        if isinstance(parent_span_id, str) and parent_span_id:
            evidence["otel_parent_span_id"] = parent_span_id
            parent_event_id = _event_id(current_trace_id, parent_span_id)
            if (current_trace_id, parent_span_id) in available:
                evidence["otel_parent_event_id"] = parent_event_id
                if causal_parent:
                    parent_ids.append(parent_event_id)
            else:
                evidence["external_parent_span_id"] = parent_span_id
                if causal_parent:
                    evidence["causal_parent_unresolved"] = True

        name = span.get("name")
        kind_override = span_attrs.get("agent.replay.kind")
        kind = kind_override if isinstance(kind_override, str) and kind_override else name
        if not isinstance(kind, str) or not kind:
            kind = "otel.span"

        status = span.get("status")
        if isinstance(status, dict):
            if "code" in status:
                evidence["otel_status_code"] = status["code"]
            if isinstance(status.get("message"), str):
                evidence["otel_status_message"] = status["message"]

        events.append({
            "event_id": _event_id(current_trace_id, span_id),
            "timestamp": _timestamp_from_unix_nano(raw_start),
            "actor": _resource_actor(resource_attrs, span_attrs),
            "kind": kind,
            "parent_ids": parent_ids,
            "observed": observed,
            "expected": expected,
            "evidence": evidence,
        })
    return events


def load_otlp_json(
    path: str | Path, *, trace_id: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> list[dict[str, Any]]:
    source = Path(path)
    size = source.stat().st_size
    if size > max_bytes:
        raise OpenTelemetryFormatError(
            f"input size {size} exceeds max_bytes={max_bytes}"
        )
    raw = source.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenTelemetryFormatError(f"invalid OTLP JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise OpenTelemetryFormatError("OTLP JSON root must be an object")
    return otlp_json_to_events(payload, trace_id=trace_id, max_events=max_events)


def write_canonical_jsonl(
    input_path: str | Path, output_path: str | Path, *, trace_id: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> Path:
    events = load_otlp_json(
        input_path, trace_id=trace_id, max_bytes=max_bytes, max_events=max_events
    )
    target = Path(output_path)
    target.write_text(
        "".join(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in events),
        encoding="utf-8",
    )
    return target
