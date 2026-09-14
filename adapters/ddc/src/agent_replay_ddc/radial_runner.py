from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any

from .radial_mapping import incident_to_radial_spec


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

    sys.path.insert(0, str(src_dir))
    spec = importlib.util.spec_from_file_location(
        "agent_replay_ddc_radial_frequency_v10",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RadialAdapterError("unable to load DDC Radial module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
    radial = _load_radial_module()
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
        "authoritative": report.authoritative,
        "claim": report.claim,
        "disposition": "CANDIDATE_FINDINGS" if hypotheses else "NO_CANDIDATES",
        "examined_nodes": report.examined_nodes,
        "examined_edges": report.examined_edges,
        "hypotheses": hypotheses,
    }


def main():
    try:
        incident = json.load(sys.stdin)
        if not isinstance(incident, dict):
            raise RadialAdapterError("incident input must be a JSON object")
        json.dump(analyze_incident(incident), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    except Exception as exc:
        if isinstance(exc, RadialAdapterError):
            message = str(exc)
        else:
            message = f"{type(exc).__name__}: {exc}"
        print(message, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
