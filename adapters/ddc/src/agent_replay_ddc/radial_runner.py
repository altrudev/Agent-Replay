from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from agent_replay import strict_json
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
        raise RadialAdapterError(f"DDC Radial module not found: {module_path}")
    pin = os.environ.get("DDC_RADIAL_SHA256", "")
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise RadialAdapterError("DDC_RADIAL_SHA256 must be an operator-supplied lowercase SHA256 pin")
    # The pin covers this source only. Imported code remains an operator trust boundary.
    for protected in (module_path, src_dir, src_dir.parent):
        info = protected.stat()
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise RadialAdapterError("DDC source and directories must have trusted ownership and no group/world write permission")
    source_bytes = module_path.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if source_sha256 != pin:
        raise RadialAdapterError("DDC Radial source SHA256 does not match operator pin")
    module_name = "agent_replay_ddc_radial_frequency_v10"
    module = types.ModuleType(module_name)
    module.__file__ = str(module_path)
    module.__package__ = ""
    missing = object()
    prior_module = sys.modules.get(module_name, missing)
    prior_path = sys.path[:]
    sys.modules[module_name] = module
    sys.path.insert(0, str(src_dir))
    try:
        code = compile(source_bytes, str(module_path), "exec")
        exec(code, module.__dict__)
    except BaseException:
        if prior_module is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior_module
        raise
    finally:
        sys.path[:] = prior_path
    return module, {"path": "src/radial_frequency_v10.py", "sha256": source_sha256}


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


def _provenance_summary(graph: dict[str, Any]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for collection in (graph.get("nodes") or [], graph.get("edges") or []):
        for item in collection:
            provenance = item.get("provenance") if isinstance(item, dict) else None
            if not isinstance(provenance, dict):
                continue
            for value in provenance.values():
                if isinstance(value, str):
                    counts[value] += 1
                elif isinstance(value, dict):
                    counts.update(v for v in value.values() if isinstance(v, str))
    return {key: counts.get(key, 0) for key in ("EXPLICIT", "INFERRED", "DEFAULT")}


def analyze_incident(incident: dict[str, Any]) -> dict[str, Any]:
    radial, engine_source = _load_radial_module()
    graph = incident_to_radial_spec(incident)
    nodes = tuple(
        radial.Node(
            item["id"], frozenset(item["dimensions"]), mutable=item["mutable"],
            authority=item["authority"], representation=item["representation"],
            consequence=item["consequence"], observable=item["observable"],
            reversible=item["reversible"],
        )
        for item in graph["nodes"]
    )
    edges = tuple(
        radial.Edge(
            item["src"], item["dst"], item["relation"], time_gap=item["time_gap"],
            independently_mutable=item["independently_mutable"],
            shared_atomic_boundary=item["shared_atomic_boundary"],
            freshness_bound=item["freshness_bound"], context_bound=item["context_bound"],
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
        "mapping_provenance": _provenance_summary(graph),
        "hypotheses": hypotheses,
    }


def main():
    parser = argparse.ArgumentParser(prog="agent-replay-ddc-radial")
    parser.add_argument("--json", action="store_true", help="emit the complete machine-readable Radial result")
    parser.add_argument("--limit", type=int, default=10, help="maximum candidates in concise output (default: 10)")
    args = parser.parse_args()
    try:
        incident = strict_json.load(sys.stdin)
        if not isinstance(incident, dict):
            raise RadialAdapterError("incident input must be a JSON object")
        result = analyze_incident(incident)
        if args.json:
            strict_json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(render_radial(incident, result, limit=max(1, args.limit)))
    except Exception as exc:
        message = str(exc) if isinstance(exc, RadialAdapterError) else f"{type(exc).__name__}: {exc}"
        print(message, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
