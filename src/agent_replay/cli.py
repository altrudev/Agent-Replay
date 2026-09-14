import argparse
import json

from .reconstruct import reconstruct


def main():
    parser = argparse.ArgumentParser(prog="agent-replay")
    sub = parser.add_subparsers(dest="command", required=True)

    reconstruct_parser = sub.add_parser(
        "reconstruct",
        help="Reconstruct an incident from a JSONL evidence stream",
    )
    reconstruct_parser.add_argument("input")

    args = parser.parse_args()

    if args.command == "reconstruct":
        print(json.dumps(reconstruct(args.input), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
