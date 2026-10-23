#!/usr/bin/env python3
from __future__ import annotations

import configparser
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.6.0"


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"release smoke failed: {' '.join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def main() -> None:
    with tempfile.TemporaryDirectory(prefix=".agent-replay-release-smoke-", dir=ROOT) as td:
        temp = Path(td)
        wheels = temp / "wheels"
        wheels.mkdir()

        # Build the wheel directly through the declared PEP 517 backend.
        # This keeps the build offline and avoids distro pip/network-stack state.
        run([
            sys.executable,
            "-c",
            (
                "from setuptools import build_meta;"
                "import sys;"
                "print(build_meta.build_wheel(sys.argv[1]))"
            ),
            str(wheels),
        ])

        wheel_files = list(wheels.glob("agent_replay-*.whl"))
        if len(wheel_files) != 1:
            raise SystemExit(f"expected one core wheel, found {wheel_files}")

        wheel_file = wheel_files[0]
        installed = temp / "installed"
        installed.mkdir()

        with zipfile.ZipFile(wheel_file) as wheel:
            names = wheel.namelist()
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts:
                    raise SystemExit(f"unsafe wheel member: {name}")

            if any(".data/" in name for name in names):
                raise SystemExit("release smoke only supports purelib wheels without .data relocation")

            entry_points = [
                name for name in names if name.endswith(".dist-info/entry_points.txt")
            ]
            if len(entry_points) != 1:
                raise SystemExit(f"expected one entry_points.txt, found {entry_points}")

            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(wheel.read(entry_points[0]).decode("utf-8"))
            if parser.get("console_scripts", "agent-replay", fallback="") != "agent_replay.cli:main":
                raise SystemExit("wheel console entry point is missing or incorrect")

            wheel.extractall(installed)

        env = dict(os.environ)
        env["PYTHONPATH"] = str(installed)

        imported = run(
            [
                sys.executable,
                "-c",
                (
                    "import agent_replay, pathlib;"
                    "print(pathlib.Path(agent_replay.__file__).resolve())"
                ),
            ],
            env=env,
            cwd=temp,
        ).stdout.strip()
        if str(installed.resolve()) not in imported:
            raise SystemExit(f"wheel package resolved outside isolated install: {imported}")

        cli_code = (
            "import sys;"
            "from agent_replay.cli import main;"
            "sys.argv=['agent-replay',*sys.argv[1:]];"
            "main()"
        )

        def cli(*args: str) -> subprocess.CompletedProcess[str]:
            return run([sys.executable, "-c", cli_code, *args], env=env, cwd=temp)

        version = cli("--version").stdout.strip()
        if version != f"agent-replay {EXPECTED_VERSION}":
            raise SystemExit(f"unexpected installed version: {version}")

        doctor = json.loads(cli("doctor").stdout)
        if doctor.get("core") != "READY" or doctor.get("version") != EXPECTED_VERSION:
            raise SystemExit(f"doctor did not report installed core READY: {doctor}")

        # Customer workflow must be available from the installed wheel, with no
        # runtime dependencies or global operator enrollment.
        customer_workspace = temp / "customer-workspace"
        initialized = json.loads(cli("customer", "init", "--workspace", str(customer_workspace)).stdout)
        if initialized.get("schema") != "agent-replay.customer-workspace.v1":
            raise SystemExit("installed customer initialization failed")
        status = json.loads(cli("customer", "status", "--workspace", str(customer_workspace)).stdout)
        if status != initialized:
            raise SystemExit("installed customer status did not preserve workspace")
        diagnostic = json.loads(cli("customer", "diagnostics", "--workspace", str(customer_workspace)).stdout)
        if diagnostic.get("status") != "PASS":
            raise SystemExit("installed customer diagnostics failed")
        run([sys.executable, "-c", "from agent_replay.customer_web import Dashboard; from agent_replay.customer_ui import HTML; assert 'Import & analyze' in HTML"], env=env, cwd=temp)

        demo = run([sys.executable, str(ROOT / "tools" / "customer_demo.py"), "--workspace", str(temp / "customer-demo")], env=env, cwd=temp)
        if json.loads(demo.stdout).get("historical_verification") != "REPRODUCED":
            raise SystemExit("installed customer lifecycle demo failed")

        incident = temp / "incident.json"
        cli(
            "reconstruct",
            str(ROOT / "examples" / "refund-750" / "events.jsonl"),
            "--json",
            "-o",
            str(incident),
        )
        incident_doc = json.loads(incident.read_text(encoding="utf-8"))
        if incident_doc.get("reconstruction_status") != "DIVERGENCE_RECONSTRUCTED":
            raise SystemExit("installed-wheel reconstruction did not reproduce expected example")

        # Exercise audit semantics through the installed wheel, not source imports.
        audit_input = temp / "audit.jsonl"
        audit_records = [
            {"event_id": name, "timestamp": "2026-01-01T00:00:00Z",
             "actor": "asserted", "kind": "check", "expected": {"x": True},
             "observed": {"x": False}}
            for name in ("a", "b")
        ]
        audit_records.append({"event_id": "missing", "timestamp": "2026-01-01T00:00:00Z",
                              "kind": "check", "expected": {"x": None}})
        audit_input.write_text("".join(json.dumps(r) + "\n" for r in audit_records))
        audit_doc = json.loads(cli("reconstruct", str(audit_input), "--json").stdout)
        if (audit_doc.get("first_divergence_order") != "AMBIGUOUS"
                or audit_doc.get("first_provable_divergence") is not None
                or len(audit_doc.get("first_provable_divergence_set", [])) != 2
                or audit_doc["timeline"][-1]["status"] != "INCOMPLETE"):
            raise SystemExit("installed-wheel audit evidence semantics failed")

        evidence_state = json.loads(cli(
            "assess-evidence", str(ROOT / "examples" / "evidence-state-v1" / "input.json")
        ).stdout)
        if (evidence_state.get("schema") != "agent-replay.evidence-state.v1"
                or evidence_state.get("approval_absence") != "NOT_ESTABLISHED"
                or evidence_state["coverage"][0]["authentication"] != "SUPPLIED_ASSERTION"):
            raise SystemExit("installed-wheel evidence-state trust boundary failed")

        # Test the signed-member boundary using only the isolated wheel/std lib.
        run([sys.executable, '-c', '''
from agent_replay.evidence_state import SCHEMA, assess, signature
key = b'wheel-smoke-test-key-0000000000000'
anchors = {'operator': {'source': 'audit', 'key': key}}
event = dict(evidence_id='e', source='audit', actor_instance_id='a',
             channel='approval', action='pay', subject='r', kind='approval',
             scope=dict(credential='c', operation='pay', resource='r', valid_until=100),
             event_at=1, observed_at=2, ingested_at=3)
manifest = dict(manifest_id='m', source='audit', actor_instance_id='a',
                channel='approval', action='pay', subject='r', start=0, end=10,
                observed_at=11, ingested_at=12, complete=True, evidence_ids=['e'])
doc = dict(schema=SCHEMA, context_id='wheel',
           decision=dict(source='audit', actor_instance_id='a', channel='approval',
                         action='pay', subject='r', credential='c', since=0, at=10),
           events=[event], receipts=[], coverage=[manifest])
def sign(record, kind):
    record['key_id'] = 'operator'
    record['signature'] = signature('wheel', kind, record, key)
sign(event, 'event')
sign(manifest, 'coverage')
assert assess(doc, trust_anchors=anchors)['approval_absence'] == 'NOT_ESTABLISHED'
event['kind'] = 'assertion'
del event['signature']
result = assess(doc, trust_anchors=anchors)
assert result['coverage'][0]['authentication'] == 'AUTHENTICATED_COVERAGE'
assert not result['coverage'][0]['usable_for_exact_horizon']
assert result['approval_absence'] == 'NOT_ESTABLISHED'
doc['events'] = []
manifest['evidence_ids'] = []
sign(manifest, 'coverage')
assert assess(doc, trust_anchors=anchors)['approval_absence'] == 'ABSENT_IN_EXACT_COVERED_SCOPE'
'''], env=env, cwd=temp)

        public = temp / "public-share.json"
        cli("export-share", str(incident), "-o", str(public))
        if not public.is_file() or not json.loads(public.read_text(encoding="utf-8")):
            raise SystemExit("installed-wheel public-share export missing or invalid")

        aps_input = ROOT / "tests" / "fixtures" / "aps-oracle-safety-check-v1" / "pass.json"
        aps_incident = temp / "aps-incident.json"
        cli(
            "reconstruct",
            str(aps_input),
            "--format",
            "aps",
            "--json",
            "-o",
            str(aps_incident),
        )
        aps_doc = json.loads(aps_incident.read_text(encoding="utf-8"))
        if aps_doc.get("execution_status") != "NO_EXECUTION_EVIDENCE":
            raise SystemExit("installed-wheel APS reconstruction crossed execution boundary")

        aps_public = temp / "aps-public-share.json"
        cli("export-share", str(aps_incident), "-o", str(aps_public))
        aps_share = json.loads(aps_public.read_text(encoding="utf-8"))
        if aps_share.get("incident", {}).get("schema") != "agent-replay.public-aps-share.v1":
            raise SystemExit("installed-wheel APS safe-share export missing or invalid")

    print("AGENT REPLAY RELEASE SMOKE PASS")


if __name__ == "__main__":
    main()
