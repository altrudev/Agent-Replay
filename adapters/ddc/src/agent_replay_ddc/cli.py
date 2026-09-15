import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from agent_replay.otel import write_canonical_jsonl
from agent_replay.reconstruct import reconstruct
from agent_replay.report import render_text

from .bridge import DDCAdapterError, run_ddc
from .radial_runner import RadialAdapterError, analyze_incident
from .render import render_radial


def _sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _reconstruct(input_path: str, input_format: str):
    if input_format == "jsonl":
        incident = reconstruct(input_path)
        incident["input_format"] = "canonical-jsonl"
        return incident

    original_sha256 = _sha256(input_path)
    with tempfile.TemporaryDirectory(prefix="agent-replay-ddc-") as tmp:
        canonical = Path(tmp) / "canonical.jsonl"
        write_canonical_jsonl(input_path, canonical)
        incident = reconstruct(str(canonical))

    incident["input_sha256"] = original_sha256
    incident["input_format"] = "otlp-json"
    return incident


def main():
    parser = argparse.ArgumentParser(prog="agent-replay-ddc")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser(
        "verify",
        help="run the generic configured DDC command over an Agent Replay incident",
    )
    verify_parser.add_argument("input")
    verify_parser.add_argument(
        "--format",
        choices=("jsonl", "otel"),
        default="jsonl",
    )

    review_parser = sub.add_parser(
        "review",
        help="reconstruct an incident and run DDC Radial analysis",
    )
    review_parser.add_argument("input")
    review_parser.add_argument(
        "--format",
        choices=("jsonl", "otel"),
        default="jsonl",
    )
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

    incident = _reconstruct(args.input, args.format)

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
