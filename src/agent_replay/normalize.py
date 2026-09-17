from __future__ import annotations

from datetime import datetime, timezone
import heapq
import json
from pathlib import Path
from typing import Any, Iterable

from .model import CanonicalEvent


class EvidenceFormatError(ValueError):
    pass


DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_PARENTS = 64
DEFAULT_MAX_DEPTH = 4096
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON value is not permitted: {value}")


def _dict(value: Any, field_name: str, line_no: int) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise EvidenceFormatError(
            f"line {line_no}: {field_name} must be an object"
        )
    return value


def _parents(raw: dict[str, Any], line_no: int, max_parents: int) -> tuple[str, ...]:
    value = raw.get("parent_ids", raw.get("parents", []))
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(
        isinstance(x, str) and x for x in value
    ):
        raise EvidenceFormatError(
            f"line {line_no}: parent_ids must be a string or list of non-empty strings"
        )
    if len(value) > max_parents:
        raise EvidenceFormatError(
            f"line {line_no}: parent_ids exceeds max_parents={max_parents}"
        )
    if len(value) != len(set(value)):
        raise EvidenceFormatError(
            f"line {line_no}: duplicate parent_ids are not permitted"
        )
    return tuple(value)


def _parse_timestamp(value: str, line_no: int) -> datetime:
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceFormatError(
            f"line {line_no}: timestamp must be RFC3339/ISO-8601"
        ) from exc

    if parsed.tzinfo is None:
        raise EvidenceFormatError(
            f"line {line_no}: timestamp must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _canonical_timestamp(value: str, line_no: int) -> str:
    parsed = _parse_timestamp(value, line_no)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _datetime_to_ns(value: datetime) -> int:
    delta = value - _EPOCH
    return (
        ((delta.days * 86400) + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000
    )


def _event_time_ns(event: CanonicalEvent) -> int:
    exact = event.evidence.get("otel_start_time_unix_nano")
    if isinstance(exact, (str, int)):
        try:
            return int(exact)
        except (TypeError, ValueError):
            raise EvidenceFormatError(
                f"line {event.source_line}: invalid otel_start_time_unix_nano"
            )
    return _datetime_to_ns(
        _parse_timestamp(event.timestamp, event.source_line or 0)
    )


def _event_from_raw(raw: dict[str, Any], line_no: int, *, max_parents: int) -> CanonicalEvent:
    event_id = raw.get("event_id")
    timestamp = raw.get("timestamp")
    kind = raw.get("kind")
    actor = raw.get("actor", "unknown")

    for name, value in (
        ("event_id", event_id),
        ("timestamp", timestamp),
        ("kind", kind),
        ("actor", actor),
    ):
        if not isinstance(value, str) or not value:
            raise EvidenceFormatError(
                f"line {line_no}: {name} must be a non-empty string"
            )

    return CanonicalEvent(
        event_id=event_id,
        timestamp=_canonical_timestamp(timestamp, line_no),
        actor=actor,
        kind=kind,
        observed=_dict(raw.get("observed"), "observed", line_no),
        expected=_dict(raw.get("expected"), "expected", line_no),
        evidence=_dict(raw.get("evidence"), "evidence", line_no),
        parent_ids=_parents(raw, line_no, max_parents),
        source_line=line_no,
    )


def _validate_and_order(events: list[CanonicalEvent], *, max_depth: int) -> list[CanonicalEvent]:
    by_id = {event.event_id: event for event in events}
    children: dict[str, list[str]] = {event.event_id: [] for event in events}
    indegree: dict[str, int] = {event.event_id: 0 for event in events}

    for event in events:
        child_time = _event_time_ns(event)
        for parent_id in event.parent_ids:
            if parent_id == event.event_id:
                raise EvidenceFormatError(
                    f"line {event.source_line}: event cannot parent itself"
                )
            parent = by_id.get(parent_id)
            if parent is None:
                raise EvidenceFormatError(
                    f"line {event.source_line}: unknown parent_id {parent_id!r}"
                )
            parent_time = _event_time_ns(parent)
            if parent_time > child_time:
                raise EvidenceFormatError(
                    f"line {event.source_line}: parent {parent_id!r} occurs after child "
                    f"{event.event_id!r}"
                )
            children[parent_id].append(event.event_id)
            indegree[event.event_id] += 1

    ready: list[tuple[int, str]] = []
    depths: dict[str, int] = {}
    for event in events:
        if indegree[event.event_id] == 0:
            heapq.heappush(ready, (_event_time_ns(event), event.event_id))
            depths[event.event_id] = 0

    ordered: list[CanonicalEvent] = []
    while ready:
        _, event_id = heapq.heappop(ready)
        event = by_id[event_id]
        ordered.append(event)
        current_depth = depths[event_id]
        if current_depth > max_depth:
            raise EvidenceFormatError(
                f"causal graph exceeds max_depth={max_depth} at {event_id!r}"
            )

        for child_id in children[event_id]:
            depths[child_id] = max(depths.get(child_id, 0), current_depth + 1)
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                child = by_id[child_id]
                heapq.heappush(ready, (_event_time_ns(child), child.event_id))

    if len(ordered) != len(events):
        cyclic = sorted(
            event_id for event_id, degree in indegree.items() if degree > 0
        )
        raise EvidenceFormatError(
            "causal parent cycle detected involving: " + ", ".join(cyclic[:10])
        )

    return ordered


def normalize_records(
    records: Iterable[dict[str, Any]],
    *,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_parents: int = DEFAULT_MAX_PARENTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(records, 1):
        if line_no > max_events:
            raise EvidenceFormatError(f"event count exceeds max_events={max_events}")
        if not isinstance(raw, dict):
            raise EvidenceFormatError(f"line {line_no}: event must be an object")
        event = _event_from_raw(raw, line_no, max_parents=max_parents)
        if event.event_id in seen:
            raise EvidenceFormatError(
                f"line {line_no}: duplicate event_id {event.event_id!r}"
            )
        seen.add(event.event_id)
        events.append(event)
    return _validate_and_order(events, max_depth=max_depth)


def normalize_jsonl(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_parents: int = DEFAULT_MAX_PARENTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[CanonicalEvent]:
    source = Path(path)
    size = source.stat().st_size
    if size > max_bytes:
        raise EvidenceFormatError(
            f"input size {size} exceeds max_bytes={max_bytes}"
        )

    records: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if len(records) >= max_events:
                raise EvidenceFormatError(f"event count exceeds max_events={max_events}")
            try:
                raw = json.loads(line, parse_constant=_reject_json_constant)
            except (json.JSONDecodeError, ValueError) as exc:
                raise EvidenceFormatError(
                    f"line {line_no}: invalid JSON: {exc}"
                ) from exc
            if not isinstance(raw, dict):
                raise EvidenceFormatError(f"line {line_no}: event must be an object")
            records.append(raw)

    return normalize_records(
        records,
        max_events=max_events,
        max_parents=max_parents,
        max_depth=max_depth,
    )
