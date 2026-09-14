import argparse
import json

from agent_replay.reconstruct import reconstruct
from .bridge import DDCAdapterError, run_ddc


def main():
    parser = argparse.ArgumentParser(prog="agent-replay-ddc")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("input")

    args = parser.parse_args()

    if args.command == "verify":
        incident = reconstruct(args.input)
        try:
            ddc = run_ddc(incident)
        except DDCAdapterError as exc:
            parser.error(str(exc))

        print(
            json.dumps(
                {
                    "schema": "agent-replay.ddc-envelope.v1",
                    "incident": incident,
                    "ddc": ddc,
                },
                indent=2,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
