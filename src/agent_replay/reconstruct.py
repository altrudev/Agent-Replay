import hashlib
import json
from pathlib import Path


def _load_jsonl(path: Path):
    events = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            event["_source_line"] = line_no
            events.append(event)
    return events


def _mismatches(event):
    expected = event.get("expected") or {}
    observed = event.get("observed") or {}
    out = []
    for key, exp in expected.items():
        got = observed.get(key)
        if got != exp:
            out.append({"field": key, "expected": exp, "observed": got})
    return out


def reconstruct(path: str):
    source = Path(path)
    events = sorted(
        _load_jsonl(source),
        key=lambda e: (e.get("timestamp", ""), e.get("event_id", "")),
    )

    first = None
    divergences = []

    for event in events:
        mismatches = _mismatches(event)
        if not mismatches:
            continue

        item = {
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "actor": event.get("actor"),
            "kind": event.get("kind"),
            "source_line": event["_source_line"],
            "evidence": event.get("evidence") or {},
            "mismatches": mismatches,
        }
        divergences.append(item)
        if first is None:
            first = item

    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    return {
        "schema": "agent-replay.incident.v1",
        "input_sha256": digest,
        "event_count": len(events),
        "first_provable_divergence": first,
        "divergences": divergences,
        "reproducibility": "CONFIRMED" if first else "NO_DIVERGENCE_FOUND",
    }
