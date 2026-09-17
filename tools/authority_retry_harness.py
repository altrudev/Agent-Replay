#!/usr/bin/env python3
"""Deterministic local execution harness for the authority-revocation case.

This is an execution harness, not a production payment integration. It drives an
in-memory authority state and payment ledger through the same sequence used by
the public reconstruction fixture, including an alternate-route retry.

The harness deliberately leaves revocation-delivery acknowledgement unresolved:
it records a propagation attempt with no acknowledgement, then exercises an
execution decision, a non-committing primary route, an alternate-route retry,
and a downstream effect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

BASE_TS = "2026-09-17T18:00:"


def _event(
    event_id: str,
    second: int,
    actor: str,
    kind: str,
    *,
    observed: dict,
    expected: dict | None = None,
    evidence: dict | None = None,
    parents: list[str] | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": f"{BASE_TS}{second:02d}.000000Z",
        "actor": actor,
        "kind": kind,
        "observed": observed,
        "expected": expected or {},
        "evidence": evidence or {},
        "parent_ids": parents or [],
    }


def run_harness() -> tuple[list[dict], dict]:
    authority = {"version": "v17", "state": "ACTIVE"}
    payment_ledger: list[str] = []
    alternate_retry_exercised = False

    events: list[dict] = []

    events.append(
        _event(
            "approval_issued",
            1,
            "approval-service",
            "approval.issued",
            observed={"approval_valid": True},
            expected={"approval_valid": True},
            evidence={"authority_version": authority["version"]},
        )
    )

    authority = {"version": "v18", "state": "REVOKED"}
    events.append(
        _event(
            "authority_revoked",
            2,
            "authority-service",
            "authority.revoked",
            observed={"authority_revoked": True},
            expected={"authority_revoked": True},
            evidence={"authority_version": authority["version"]},
            parents=["approval_issued"],
        )
    )

    # Deliberately unresolved: the harness attempts propagation but captures no
    # delivery acknowledgement from the execution boundary.
    events.append(
        _event(
            "revocation_propagation",
            3,
            "authority-service",
            "authority.propagation",
            observed={"delivery_acknowledged": False},
            evidence={"attempted": True},
            parents=["authority_revoked"],
        )
    )

    # Simulate a stale cached execution decision made after revocation.
    execution_permitted = True
    events.append(
        _event(
            "execution_decision",
            4,
            "payment-agent",
            "execution.decision",
            observed={"execution_permitted": execution_permitted},
            expected={"execution_permitted": False},
            evidence={"observed_authority_version": "v17"},
            parents=["approval_issued", "authority_revoked"],
        )
    )

    # Primary route is exercised but does not commit. It returns an ambiguous
    # transport outcome, causing the agent to take the alternate route.
    primary_committed = False
    events.append(
        _event(
            "primary_route_attempt",
            5,
            "payment-router",
            "execution.primary_route",
            observed={"committed": primary_committed},
            expected={"committed": False},
            evidence={"outcome": "AMBIGUOUS_NO_COMMIT"},
            parents=["execution_decision"],
        )
    )

    alternate_retry_exercised = True
    events.append(
        _event(
            "alternate_route_retry",
            6,
            "payment-agent",
            "execution.alternate_route_retry",
            observed={"retry_permitted": alternate_retry_exercised},
            expected={"retry_permitted": False},
            evidence={"route": "alternate"},
            parents=["execution_decision", "primary_route_attempt"],
        )
    )

    if alternate_retry_exercised:
        payment_ledger.append("txn-synthetic-001")

    events.append(
        _event(
            "payment_executed",
            7,
            "payment-api",
            "payment.executed",
            observed={"transfer_executed": bool(payment_ledger)},
            expected={"transfer_executed": False},
            evidence={"ledger_count": len(payment_ledger)},
            parents=["alternate_route_retry"],
        )
    )

    result = {
        "schema": "agent-replay.execution-harness-result.v1",
        "harness_type": "deterministic-local-in-memory",
        "production_integration": False,
        "expected_behavior_basis": "HARNESS_POLICY_ASSERTIONS",
        "expected_behavior_scope": (
            "The expected-state assertions are test-harness inputs and are not "
            "independently authenticated policy truth."
        ),
        "alternate_route_retry_exercised": alternate_retry_exercised,
        "primary_route_committed": primary_committed,
        "downstream_effect_count": len(payment_ledger),
        "revocation_delivery_acknowledgement_captured": False,
        "independently_checkable_without_ddc": True,
        "reproduction_command": (
            "python3 tools/authority_retry_harness.py --events /tmp/authority-retry-events.jsonl "
            "--result /tmp/authority-retry-harness.json && agent-replay reconstruct "
            "/tmp/authority-retry-events.jsonl --json"
        ),
    }
    return events, result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True, help="output canonical JSONL path")
    parser.add_argument("--result", required=True, help="output harness result JSON path")
    args = parser.parse_args()

    events, result = run_harness()
    events_path = Path(args.events)
    result_path = Path(args.result)

    events_bytes = b"".join(
        (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for event in events
    )
    events_path.write_bytes(events_bytes)

    result["events_sha256"] = hashlib.sha256(events_bytes).hexdigest()
    result["harness_source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
