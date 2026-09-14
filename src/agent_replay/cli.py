import argparse
import json
import tempfile
from pathlib import Path

from .otel import write_canonical_jsonl
from .reconstruct import reconstruct
from .report import render_text


def _emit(incident, as_json: bool):
    if as_json:
        print(json.dumps(incident, indent=2, sort_keys=True))
    else:
        print(render_text(incident))


def main():
    parser = argparse.ArgumentParser(prog="agent-replay")
    sub = parser.add_subparsers(dest="command", required=True)

    reconstruct_parser = sub.add_parser(
        "reconstruct",
        help="Reconstruct an incident from canonical JSONL or OTLP JSON",
    )
    reconstruct_parser.add_argument("input")
    reconstruct_parser.add_argument(
        "--format",
        choices=("jsonl", "otel"),
        default="jsonl",
        help="input format (default: jsonl)",
    )
    reconstruct_parser.add_argument(
        "--json",
        action="store_true",
        help="emit the machine-readable incident document",
    )

    ingest_parser = sub.add_parser(
        "ingest",
        help="Normalize external telemetry into Agent Replay canonical JSONL",
    )
    ingest_sub = ingest_parser.add_subparsers(dest="ingest_format", required=True)

    otel_parser = ingest_sub.add_parser(
        "otel",
        help="Normalize OpenTelemetry OTLP JSON",
    )
    otel_parser.add_argument("input")
    otel_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="canonical JSONL output path",
    )

    args = parser.parse_args()

    if args.command == "ingest" and args.ingest_format == "otel":
        target = write_canonical_jsonl(args.input, args.output)
        print(str(target))
        return

    if args.command == "reconstruct":
        if args.format == "jsonl":
            _emit(reconstruct(args.input), args.json)
            return

        with tempfile.TemporaryDirectory(prefix="agent-replay-otel-") as tmp:
            canonical = Path(tmp) / "canonical.jsonl"
            write_canonical_jsonl(args.input, canonical)
            _emit(reconstruct(str(canonical)), args.json)


if __name__ == "__main__":
    main()
