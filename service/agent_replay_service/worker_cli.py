from __future__ import annotations

import json
import sys

from agent_replay.reconstruct import reconstruct


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    report = reconstruct(sys.argv[1])
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
