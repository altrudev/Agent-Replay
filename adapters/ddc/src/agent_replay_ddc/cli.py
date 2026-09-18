import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from agent_replay.aps import reconstruct_aps_fixture
from agent_replay.otel import write_canonical_jsonl
from agent_replay.reconstruct import reconstruct
from agent_replay.report import render_text

from .bridge import DDCAdapterError, run_ddc
from .radial_runner import RadialAdapterError, analyze_incident
from .render import render_radial


def _sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _reconstruct(
    input_path: str,
    input_format: str,
    trace_id: str | None = None,
    source_repository: str | None = None,
    source_revision: str | None = None,
    source_path: str | None = None,
):
    if input_format == "aps":
        if trace_id:
            raise ValueError("trace_id is not valid for APS input")
        raw = Path(input_path).read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("APS input must be a JSON object")
        incident = reconstruct_aps_fixture(
            document,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            input_provenance={
                "repository": source_repository,
                "revision": source_revision,
                "path": source_path,
            },
        )
        incident["input_sha256"] = hashlib.sha256(raw).hexdigest()
        incident["input_format"] = "aps-oracle-safety-check-v1"
        return incident

    if input_format == "jsonl":
        if trace_id:
            raise ValueError("trace_id is only valid for OTLP input")
        incident = reconstruct(input_path)
        incident["input_format"] = "canonical-jsonl"
        return incident

    original_sha256 = _sha256(input_path)
    with tempfile.TemporaryDirectory(prefix="agent-replay-ddc-") as tmp:
        canonical = Path(tmp) / "canonical.jsonl"
        write_canonical_jsonl(
            input_path,
            canonical,
            trace_id=trace_id,
        )
        incident = reconstruct(str(canonical))

    incident["input_sha256"] = original_sha256
    incident["input_format"] = "otlp-json"
    if trace_id:
        incident["selected_trace_id"] = trace_id
    return incident


def _add_input_args(target):
    target.add_argument("input")
    target.add_argument(
        "--format",
        choices=("jsonl", "otel", "aps"),
        default="jsonl",
    )
    target.add_argument(
        "--trace-id",
        help="trace ID to select when an OTLP document contains multiple traces",
    )
    target.add_argument("--source-repository", help="APS input source repository; not inferred")
    target.add_argument("--source-revision", help="APS input source revision; not inferred")
    target.add_argument("--source-path", help="APS input source path; not inferred")


def main():
    parser = argparse.ArgumentParser(prog="agent-replay-ddc")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser(
        "verify",
        help="run the generic configured DDC command over an Agent Replay incident",
    )
    _add_input_args(verify_parser)

    review_parser = sub.add_parser(
        "review",
        help="reconstruct an incident and run DDC Radial analysis",
    )
    _add_input_args(review_parser)
    review_parser.add_argument(
        "--json",
        action="store_true",
        help="emit complete Agent Replay + DDC Radial JSON",
    )
    review_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="maximum Radial candidates in concise output",
    )

    args = parser.parse_args()

    try:
        incident = _reconstruct(args.input, args.format, args.trace_id, args.source_repository, args.source_revision, args.source_path)
    except ValueError as exc:
        parser.error(str(exc))

    if args.command == "verify":
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
        return

    if args.command == "review":
        try:
            radial = analyze_incident(incident)
        except RadialAdapterError as exc:
            parser.error(str(exc))

        if args.json:
            print(
                json.dumps(
                    {
                        "schema": "agent-replay.ddc-review.v1",
                        "incident": incident,
                        "radial": radial,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        print(render_text(incident))
        print()
        print(render_radial(incident, radial, limit=max(1, args.limit)))


if __name__ == "__main__":
    main()
