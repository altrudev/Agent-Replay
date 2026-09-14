from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    timestamp: str
    actor: str
    kind: str
    observed: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    parent_ids: tuple[str, ...] = ()
    source_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "kind": self.kind,
            "observed": self.observed,
            "expected": self.expected,
            "evidence": self.evidence,
            "parent_ids": list(self.parent_ids),
            "source_line": self.source_line,
        }
