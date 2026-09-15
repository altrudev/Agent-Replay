from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types
from typing import Any

from .radial_mapping import incident_to_radial_spec
from .render import render_radial


class RadialAdapterError(RuntimeError):
    pass


def _load_radial_module():
    root = os.environ.get("DDC_RADIAL_ROOT")
    if not root:
        raise RadialAdapterError(
            "DDC_RADIAL_ROOT is not set. Point it at a local DDC checkout. "
            "Agent Replay core does not require DDC."
        )

    src_dir = Path(root).expanduser().resolve() / "src"
    module_path = src_dir / "radial_frequency_v10.py"
    if not module_path.is_file():
        raise RadialAdapterError(
            f"DDC Radial module not found: {module_path}"
        )

    # Hash and execute the same byte buffer: no hash/load TOCTOU gap.
    source_bytes = module_path.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    module_name = "agent_replay_ddc_radial_frequency_v10"
    module = types.ModuleType(module_name)
    module.__file__ = str(module_path)
    module.__package__ = ""
    sys.modules[module_name] = module

    sys.path.insert(0, str(src_dir))
    try:
        code = compile(source_bytes, str(module_path), "exec")
        exec(code, module.__dict__)
    finally:
        try:
            sys.path.remove(str(src_dir))
        except ValueError:
            pass

    return module, {
        "path": "src/radial_frequency_v10.py",
        "sha256": source_sha256,
    }

def _hypothesis_to_dict(hypothesis) -> dict[str, Any]:
    return {
        "prior_id": hypothesis.prior_id,
        "title": hypothesis.title,
        "score": hypothesis.score,
        "subjects": list(hypothesis.subjects),
        "features": dict(hypothesis.features.as_dict()),
        "falsification_test": hypothesis.falsification_test,
        "rationale": hypothesis.rationale,
        "disposition": hypothesis.disposition,
    }


def analyze_incident(incident: dict[str, Any]) -> dict[str, Any]:
    radial, engine_source = _load_radial_module()
    graph = incident_to_radial_spec(incident)

    nodes = tuple(
        radial.Node(
            item["id"],
            frozenset(item["dimensions"]),
            mutable=item["mutable"],
            authority=item["authority"],
            representation=item["representation"],
            consequence=item["consequence"],
            observable=item["observable"],
            reversible=item["reversible"],
        )
        for item in graph["nodes"]
    )

    edges = tuple(
        radial.Edge(
            item["src"],
            item["dst"],
            item["relation"],
            time_gap=item["time_gap"],
            independently_mutable=item["independently_mutable"],
            shared_atomic_boundary=item["shared_atomic_boundary"],
            freshness_bound=item["freshness_bound"],
            context_bound=item["context_bound"],
        )
        for item in graph["edges"]
    )

    report = radial.RadialFrequency().analyze(nodes, edges)
    hypotheses = [_hypothesis_to_dict(item) for item in report.hypotheses]

    return {
        "adapter_schema": "agent-replay.ddc-radial.v1",
        "engine": report.engine,
        "engine_source": engine_source,
        "authoritative": report.authoritative,
        "claim": report.claim,
        "disposition": "CANDIDATE_FINDINGS" if hypotheses else "NO_CANDIDATES",
        "examined_nodes": report.examined_nodes,
        "examined_edges": report.examined_edges,
        "hypotheses": hypotheses,
    }


def main():
    parser = argparse.ArgumentParser(prog="agent-replay-ddc-radial")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the complete machine-readable Radial result",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="maximum candidates in concise output (default: 10)",
    )
    args = parser.parse_args()

    try:
        incident = json.load(sys.stdin)
        if not isinstance(incident, dict):
            raise RadialAdapterError("incident input must be a JSON object")

        result = analyze_incident(incident)

        if args.json:
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(render_radial(incident, result, limit=max(1, args.limit)))

    except Exception as exc:
        if isinstance(exc, RadialAdapterError):
            message = str(exc)
        else:
            message = f"{type(exc).__name__}: {exc}"
        print(message, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
