import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from .otel import write_canonical_jsonl
from .reconstruct import reconstruct
from .report import render_text
from .share import write_share_bundle
from .trace import render_trace_summary, verify_trace_record


def _emit(incident, as_json: bool):
    if as_json:
        print(json.dumps(incident, indent=2, sort_keys=True))
    else:
        print(render_text(incident))


def _sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _supplementary_bundle_sha256(incident: dict, trace_summary: dict) -> str:
    payload = {
        "input_sha256": incident["input_sha256"],
        "canonical_sha256": incident["canonical_sha256"],
        "trace_record_sha256": trace_summary["record_sha256"],
        "trace_trusted_key_sha256": trace_summary["trusted_key_sha256"],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
        "--trace-id",
        help="trace ID to select when an OTLP document contains multiple traces",
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
        "--trace-id",
        help="trace ID to select when an OTLP document contains multiple traces",
    )
    otel_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="canonical JSONL output path",
    )

    share_parser = sub.add_parser(
        "export-share",
        help="Create an allowlist-only evidence bundle safe for external sharing",
    )
    share_parser.add_argument("incident", help="machine-readable Agent Replay incident JSON")
    share_parser.add_argument("-o", "--output", required=True, help="output JSON path")
    share_parser.add_argument("--radial", help="optional DDC Radial JSON review")
    share_parser.add_argument(
        "--agent-replay-commit",
        help="optional Agent Replay commit identifier to bind into the public bundle",
    )

    args = parser.parse_args()

    if args.command == "ingest" and args.ingest_format == "otel":
        target = write_canonical_jsonl(
            args.input,
            args.output,
            trace_id=args.trace_id,
        )
        print(str(target))
        return

    if args.command == "verify-trace":
        summary = verify_trace_record(args.record, args.trusted_key)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(render_trace_summary(summary))
        return

    if args.command == "export-share":
        target = write_share_bundle(
            args.incident,
            args.output,
            radial_path=args.radial,
            agent_replay_commit=args.agent_replay_commit,
        )
        print(str(target))
        return

    if args.command == "reconstruct":
        if bool(args.trace_record) != bool(args.trace_key):
            parser.error("--trace-record and --trace-key must be supplied together")
        if args.format == "jsonl" and args.trace_id:
            parser.error("--trace-id is only valid with --format otel")

        trace_summary = None
        if args.trace_record:
            trace_summary = verify_trace_record(args.trace_record, args.trace_key)

        if args.format == "jsonl":
            incident = reconstruct(args.input)
            incident["input_format"] = "canonical-jsonl"
        else:
            original_sha256 = _sha256(args.input)
            with tempfile.TemporaryDirectory(prefix="agent-replay-otel-") as tmp:
                canonical = Path(tmp) / "canonical.jsonl"
                write_canonical_jsonl(
                    args.input,
                    canonical,
                    trace_id=args.trace_id,
                )
                incident = reconstruct(str(canonical))
            incident["input_sha256"] = original_sha256
            incident["input_format"] = "otlp-json"
            if args.trace_id:
                incident["selected_trace_id"] = args.trace_id

        if trace_summary is not None:
            incident["trace_evidence"] = trace_summary
            incident["supplementary_evidence_bundle_sha256"] = (
                _supplementary_bundle_sha256(incident, trace_summary)
            )

        _emit(incident, args.json)


if __name__ == "__main__":
    main()
