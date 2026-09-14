from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .model import CanonicalEvent


class EvidenceFormatError(ValueError):
    pass


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


def _validate_graph(events: list[CanonicalEvent]) -> None:
    by_id = {event.event_id: event for event in events}

    for event in events:
        child_time = _parse_timestamp(event.timestamp, event.source_line or 0)
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
            parent_time = _parse_timestamp(parent.timestamp, parent.source_line or 0)
            if parent_time > child_time:
                raise EvidenceFormatError(
                    f"line {event.source_line}: parent {parent_id!r} occurs after child "
                    f"{event.event_id!r}"
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(event_id: str) -> None:
        if event_id in visited:
            return
        if event_id in visiting:
            raise EvidenceFormatError(
                f"causal parent cycle detected at event {event_id!r}"
            )
        visiting.add(event_id)
        for parent_id in by_id[event_id].parent_ids:
            visit(parent_id)
        visiting.remove(event_id)
        visited.add(event_id)

    for event_id in by_id:
        visit(event_id)


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
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceFormatError(
                    f"line {line_no}: invalid JSON: {exc.msg}"
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

    _validate_graph(events)
    return sorted(
        events,
        key=lambda event: (
            _parse_timestamp(event.timestamp, event.source_line or 0),
            event.event_id,
        ),
    )
