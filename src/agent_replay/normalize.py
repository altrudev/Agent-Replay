from __future__ import annotations

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
        return (value,)
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise EvidenceFormatError(
            f"line {line_no}: parent_ids must be a string or list of strings"
        )
    return tuple(value)


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
                    timestamp=timestamp,
                    actor=actor,
                    kind=kind,
                    observed=_dict(raw.get("observed"), "observed", line_no),
                    expected=_dict(raw.get("expected"), "expected", line_no),
                    evidence=_dict(raw.get("evidence"), "evidence", line_no),
                    parent_ids=_parents(raw, line_no),
                    source_line=line_no,
                )
            )

    return sorted(events, key=lambda e: (e.timestamp, e.event_id))
