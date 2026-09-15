from __future__ import annotations

from datetime import datetime, timezone
import heapq
import json
from pathlib import Path
from typing import Any

from .model import CanonicalEvent


class EvidenceFormatError(ValueError):
    pass


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


def _parents(raw: dict[str, Any], line_no: int) -> tuple[str, ...]:
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


def _validate_and_order(events: list[CanonicalEvent]) -> list[CanonicalEvent]:
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
    for event in events:
        if indegree[event.event_id] == 0:
            heapq.heappush(
                ready,
                (_event_time_ns(event), event.event_id),
            )

    ordered: list[CanonicalEvent] = []
    while ready:
        _, event_id = heapq.heappop(ready)
        event = by_id[event_id]
        ordered.append(event)

        for child_id in children[event_id]:
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                child = by_id[child_id]
                heapq.heappush(
                    ready,
                    (_event_time_ns(child), child.event_id),
                )

    if len(ordered) != len(events):
        cyclic = sorted(
            event_id for event_id, degree in indegree.items() if degree > 0
        )
        raise EvidenceFormatError(
            "causal parent cycle detected involving: " + ", ".join(cyclic[:10])
        )

    return ordered


def normalize_jsonl(path: str | Path) -> list[CanonicalEvent]:
    source = Path(path)
    events: list[CanonicalEvent] = []
    seen: set[str] = set()

    with source.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line, parse_constant=_reject_json_constant)
            except (json.JSONDecodeError, ValueError) as exc:
                raise EvidenceFormatError(
                    f"line {line_no}: invalid JSON: {exc}"
                ) from exc

            if not isinstance(raw, dict):
                raise EvidenceFormatError(f"line {line_no}: event must be an object")

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

            if event_id in seen:
                raise EvidenceFormatError(
                    f"line {line_no}: duplicate event_id {event_id!r}"
                )
            seen.add(event_id)

            events.append(
                CanonicalEvent(
                    event_id=event_id,
                    timestamp=_canonical_timestamp(timestamp, line_no),
                    actor=actor,
                    kind=kind,
                    observed=_dict(raw.get("observed"), "observed", line_no),
                    expected=_dict(raw.get("expected"), "expected", line_no),
                    evidence=_dict(raw.get("evidence"), "evidence", line_no),
                    parent_ids=_parents(raw, line_no),
                    source_line=line_no,
                )
            )

    return _validate_and_order(events)
