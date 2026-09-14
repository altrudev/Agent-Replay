import argparse
import json

from .reconstruct import reconstruct
from .report import render_text


def main():
    parser = argparse.ArgumentParser(prog="agent-replay")
    sub = parser.add_subparsers(dest="command", required=True)

    reconstruct_parser = sub.add_parser(
        "reconstruct",
        help="Reconstruct an incident from a JSONL evidence stream",
    )
    reconstruct_parser.add_argument("input")
    reconstruct_parser.add_argument(
        "--json",
        action="store_true",
        help="emit the machine-readable incident document",
    )

    args = parser.parse_args()

    if args.command == "reconstruct":
        incident = reconstruct(args.input)
        if args.json:
            print(json.dumps(incident, indent=2, sort_keys=True))
        else:
            print(render_text(incident))


if __name__ == "__main__":
    main()
