from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time
import tracemalloc

from agent_replay.reconstruct import reconstruct


def _write_fixture(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for index in range(count):
            event = {
                "event_id": f"e{index}",
                "timestamp": f"2026-09-17T00:{(index // 60) % 60:02d}:{index % 60:02d}Z",
                "actor": "benchmark-agent",
                "kind": "tool.write",
                "parent_ids": [f"e{index - 1}"] if index else [],
                "observed": {"state": index},
                "expected": {"state": index if index % 100 else -1},
                "evidence": {},
            }
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")


def run(count: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="agent-replay-bench-") as tmp:
        path = Path(tmp) / "events.jsonl"
        _write_fixture(path, count)
        tracemalloc.start()
        started = time.perf_counter()
        incident = reconstruct(path, max_events=count + 1, max_depth=count + 1)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {
            "events": count,
            "seconds": round(elapsed, 6),
            "events_per_second": round(count / elapsed, 2) if elapsed else None,
            "peak_bytes": peak,
            "canonical_sha256": incident["canonical_sha256"],
            "divergences": len(incident["divergences"]),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, nargs="+", default=[1000, 10000, 100000])
    args = parser.parse_args()
    print(json.dumps([run(count) for count in args.events], indent=2))


if __name__ == "__main__":
    main()
