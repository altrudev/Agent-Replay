import argparse
import json
import tempfile
from pathlib import Path

from .otel import write_canonical_jsonl
from .reconstruct import reconstruct
from .report import render_text
from .trace import render_trace_summary, verify_trace_record


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
    reconstruct_parser.add_argument(
        "--trace-record",
        help="optional standalone TRACE Trust Record to verify and attach",
    )
    reconstruct_parser.add_argument(
        "--trace-key",
        help="trusted TRACE issuer public key (PEM or JWK JSON)",
    )

    verify_trace_parser = sub.add_parser(
        "verify-trace",
        help="Verify a standalone TRACE Trust Record against a trusted issuer key",
    )
    verify_trace_parser.add_argument("record")
    verify_trace_parser.add_argument(
        "--trusted-key",
        required=True,
        help="trusted issuer public key (PEM or JWK JSON)",
    )
    verify_trace_parser.add_argument(
        "--json",
        action="store_true",
        help="emit the verification summary as JSON",
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

    if args.command == "verify-trace":
        summary = verify_trace_record(args.record, args.trusted_key)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(render_trace_summary(summary))
        return

    if args.command == "reconstruct":
        if bool(args.trace_record) != bool(args.trace_key):
            parser.error("--trace-record and --trace-key must be supplied together")

        trace_summary = None
        if args.trace_record:
            trace_summary = verify_trace_record(args.trace_record, args.trace_key)

        if args.format == "jsonl":
            incident = reconstruct(args.input)
        else:
            with tempfile.TemporaryDirectory(prefix="agent-replay-otel-") as tmp:
                canonical = Path(tmp) / "canonical.jsonl"
                write_canonical_jsonl(args.input, canonical)
                incident = reconstruct(str(canonical))

        if trace_summary is not None:
            incident["trace_evidence"] = trace_summary

        _emit(incident, args.json)


if __name__ == "__main__":
    main()
