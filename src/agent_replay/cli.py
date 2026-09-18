import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
from pathlib import Path

from .aps import reconstruct_aps_fixture
from .normalize import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_EVENTS,
    DEFAULT_MAX_PARENTS,
)
from .otel import load_otlp_json, write_canonical_jsonl
from .reconstruct import reconstruct, reconstruct_records
from .reproduce import compare_reconstruction
from .report import render_text
from .share import write_share_bundle
from .trace import render_trace_summary, verify_trace_record


def _version() -> str:
    try:
        return importlib.metadata.version("agent-replay")
    except importlib.metadata.PackageNotFoundError:
        return "0+unknown"


def _write_output(text: str, output: str | None) -> None:
    if output and output != "-":
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _emit(value, as_json: bool, output: str | None = None):
    if as_json:
        text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    else:
        text = render_text(value)
        if not text.endswith("\n"):
            text += "\n"
    _write_output(text, output)


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _supplementary_bundle_sha256(incident: dict, trace_summary: dict) -> str:
    payload = {
        "input_sha256": incident["input_sha256"],
        "canonical_sha256": incident["canonical_sha256"],
        "trace_record_sha256": trace_summary["record_sha256"],
        "trace_trusted_key_sha256": trace_summary["trusted_key_sha256"],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _attach_trace_evidence(incident: dict, record: str, trusted_key: str) -> None:
    trace_summary = verify_trace_record(record, trusted_key)
    incident["trace_evidence"] = trace_summary
    incident["supplementary_evidence_bundle_sha256"] = _supplementary_bundle_sha256(
        incident, trace_summary
    )


def _detect_format(path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".json":
        source = Path(path)
        try:
            if source.stat().st_size > max_bytes:
                return "otel"
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "otel"
        if isinstance(raw, dict) and isinstance(raw.get("envelope"), dict):
            envelope = raw["envelope"]
            if "intent" in envelope and "decision" in envelope and "delegations" in envelope:
                return "aps"
        return "otel"
    return "jsonl"


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    parser.add_argument("--max-parents", type=int, default=DEFAULT_MAX_PARENTS)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)


def _reconstruct_input(args) -> dict:
    fmt = _detect_format(args.input, max_bytes=args.max_bytes) if args.format == "auto" else args.format
    if fmt == "aps":
        if args.trace_id:
            raise ValueError("--trace-id is not valid with APS input")
        source = Path(args.input)
        size = source.stat().st_size
        if size > args.max_bytes:
            raise ValueError(f"input size {size} exceeds max_bytes={args.max_bytes}")
        raw = source.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("APS input must be a JSON object")
        input_sha256 = hashlib.sha256(raw).hexdigest()
        incident = reconstruct_aps_fixture(document, input_sha256=input_sha256)
        incident["input_format"] = "aps-oracle-safety-check-v1"
        return incident

    if fmt == "jsonl":
        if args.trace_id:
            raise ValueError("--trace-id is only valid with OTLP input")
        incident = reconstruct(
            args.input,
            max_bytes=args.max_bytes,
            max_events=args.max_events,
            max_parents=args.max_parents,
            max_depth=args.max_depth,
        )
        incident["input_format"] = "canonical-jsonl"
        return incident

    source = Path(args.input)
    size = source.stat().st_size
    if size > args.max_bytes:
        raise ValueError(f"input size {size} exceeds max_bytes={args.max_bytes}")
    original_sha256 = _sha256(args.input)
    events = load_otlp_json(
        args.input,
        trace_id=args.trace_id,
        max_bytes=args.max_bytes,
        max_events=args.max_events,
    )
    incident = reconstruct_records(
        events,
        input_sha256=original_sha256,
        max_events=args.max_events,
        max_parents=args.max_parents,
        max_depth=args.max_depth,
    )
    incident["input_format"] = "otlp-json"
    if args.trace_id:
        incident["selected_trace_id"] = args.trace_id
    return incident


def _doctor() -> dict:
    trace_available = True
    try:
        importlib.metadata.version("agentrust-trace")
    except importlib.metadata.PackageNotFoundError:
        trace_available = False
    radial_root = os.environ.get("DDC_RADIAL_ROOT")
    radial_module = None
    if radial_root:
        radial_module = str(Path(radial_root).expanduser() / "src" / "radial_frequency_v10.py")
    return {
        "schema": "agent-replay.doctor.v1",
        "version": _version(),
        "core": "READY",
        "trace_optional_dependency": "AVAILABLE" if trace_available else "NOT_INSTALLED",
        "ddc_radial_root_set": bool(radial_root),
        "ddc_radial_module_present": bool(radial_module and Path(radial_module).is_file()),
    }


def _run(args, parser: argparse.ArgumentParser) -> None:
    if args.command == "doctor":
        result = _doctor()
        _write_output(json.dumps(result, indent=2, sort_keys=True) + "\n", args.output)
        return

    if args.command == "ingest" and args.ingest_format == "otel":
        target = write_canonical_jsonl(
            args.input,
            args.output,
            trace_id=args.trace_id,
            max_bytes=args.max_bytes,
            max_events=args.max_events,
        )
        print(str(target))
        return

    if args.command == "verify-trace":
        summary = verify_trace_record(args.record, args.trusted_key)
        text = json.dumps(summary, indent=2, sort_keys=True) + "\n" if args.json else render_trace_summary(summary) + "\n"
        _write_output(text, args.output)
        return

    if args.command == "export-share":
        target = write_share_bundle(
            args.incident,
            args.output,
            radial_path=args.radial,
            agent_replay_commit=args.agent_replay_commit,
            include_values=args.include_values,
        )
        print(str(target))
        return

    if args.command == "reconstruct":
        if bool(args.trace_record) != bool(args.trace_key):
            parser.error("--trace-record and --trace-key must be supplied together")
        incident = _reconstruct_input(args)
        if args.trace_record:
            if str(incident.get("schema", "")).startswith("agent-replay.aps-authority-reconstruction."):
                raise ValueError("TRACE supplementary evidence is not supported for APS reconstruction")
            _attach_trace_evidence(incident, args.trace_record, args.trace_key)
        _emit(incident, args.json, args.output)
        return

    if args.command == "reproduce":
        if bool(args.trace_record) != bool(args.trace_key):
            parser.error("--trace-record and --trace-key must be supplied together")
        expected = json.loads(Path(args.incident).read_text(encoding="utf-8"))
        replay_args = argparse.Namespace(**vars(args))
        replay_args.input = args.evidence
        observed = _reconstruct_input(replay_args)
        if args.trace_record:
            _attach_trace_evidence(observed, args.trace_record, args.trace_key)
        result = compare_reconstruction(expected, observed)
        _write_output(json.dumps(result, indent=2, sort_keys=True) + "\n", args.output)
        if result["status"] != "REPRODUCED":
            raise SystemExit(3)
        return


def main():
    parser = argparse.ArgumentParser(prog="agent-replay")
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    parser.add_argument("--debug", action="store_true", help="show tracebacks for failures")
    sub = parser.add_subparsers(dest="command", required=True)

    reconstruct_parser = sub.add_parser("reconstruct", help="Reconstruct an incident from canonical JSONL or OTLP JSON")
    reconstruct_parser.add_argument("input")
    reconstruct_parser.add_argument("--format", choices=("auto", "jsonl", "otel", "aps"), default="auto")
    reconstruct_parser.add_argument("--trace-id")
    reconstruct_parser.add_argument("--json", action="store_true")
    reconstruct_parser.add_argument("-o", "--output", help="output path; default stdout")
    reconstruct_parser.add_argument("--trace-record")
    reconstruct_parser.add_argument("--trace-key")
    _add_limits(reconstruct_parser)

    reproduce_parser = sub.add_parser("reproduce", help="Re-run evidence and compare deterministic reconstruction outputs")
    reproduce_parser.add_argument("incident", help="previous machine-readable incident JSON")
    reproduce_parser.add_argument("evidence", help="source evidence to replay")
    reproduce_parser.add_argument("--format", choices=("auto", "jsonl", "otel"), default="auto")
    reproduce_parser.add_argument("--trace-id")
    reproduce_parser.add_argument("--trace-record", help="TRACE record used by the original incident, when applicable")
    reproduce_parser.add_argument("--trace-key", help="caller-supplied trusted TRACE key used by the original incident")
    reproduce_parser.add_argument("-o", "--output", help="output path; default stdout")
    _add_limits(reproduce_parser)

    verify_trace_parser = sub.add_parser("verify-trace", help="Verify a standalone TRACE Trust Record")
    verify_trace_parser.add_argument("record")
    verify_trace_parser.add_argument("--trusted-key", required=True)
    verify_trace_parser.add_argument("--json", action="store_true")
    verify_trace_parser.add_argument("-o", "--output")

    ingest_parser = sub.add_parser("ingest", help="Normalize external telemetry into Agent Replay canonical JSONL")
    ingest_sub = ingest_parser.add_subparsers(dest="ingest_format", required=True)
    otel_parser = ingest_sub.add_parser("otel", help="Normalize OpenTelemetry OTLP JSON")
    otel_parser.add_argument("input")
    otel_parser.add_argument("--trace-id")
    otel_parser.add_argument("-o", "--output", required=True)
    otel_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    otel_parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)

    share_parser = sub.add_parser("export-share", help="Create an allowlist-only evidence bundle safe for external sharing")
    share_parser.add_argument("incident")
    share_parser.add_argument("-o", "--output", required=True)
    share_parser.add_argument("--radial")
    share_parser.add_argument("--agent-replay-commit")
    share_parser.add_argument("--include-values", action="store_true", help="explicitly include scalar assertion values; default is redacted")

    doctor_parser = sub.add_parser("doctor", help="Check core and optional integration readiness")
    doctor_parser.add_argument("-o", "--output")

    args = parser.parse_args()
    try:
        _run(args, parser)
    except SystemExit:
        raise
    except Exception as exc:
        if args.debug:
            raise
        print(f"agent-replay: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
