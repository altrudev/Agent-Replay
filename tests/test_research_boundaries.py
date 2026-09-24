"""Original synthetic regressions by Valentyn Rukhaylo / Altru.dev.

Motivation: PlanFence (arXiv:2609.03340), SARA (arXiv:2608.27146).
No upstream code/vectors copied. Tests reconstruction, not enforcement.
"""
import copy
import hashlib
import json

import pytest
from agent_replay.reconstruct import reconstruct_records


def event(identifier, second, kind, **fields):
    return dict(event_id=identifier, timestamp=f"2026-09-24T00:00:{second:02d}Z",
                actor="synthetic-agent", kind=kind, **fields)


def replay(records):
    digest = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    return reconstruct_records(records, input_sha256=digest)


@pytest.mark.parametrize("replanned", [False, True])
def test_fresh_memory_does_not_revalidate_old_plan(replanned):
    records = [
        event("plan", 0, "plan.created", evidence={"dependency_version": "r3"}),
        event("refresh", 1, "memory.refreshed", expected={"version": "r4"}, observed={"version": "r4"}),
        event("execute", 2, "action.executed", parent_ids=["plan", "refresh"],
              expected={"plan_dependency_version": "r4"},
              observed={"plan_dependency_version": "r4" if replanned else "r3"}),
    ]
    report = replay(records)
    assert report["timeline"][1]["status"] == "VALID"
    if replanned:
        assert report["first_provable_divergence"] is None
    else:
        assert report["first_provable_divergence"]["event_id"] == "execute"
        assert report["first_provable_divergence"]["mismatches"][0]["field"] == "plan_dependency_version"
    assert report["expectation_scope"].startswith("CALLER_SUPPLIED_ASSERTIONS")


@pytest.mark.parametrize("repetitions", [1, 3, 12])
def test_repetition_and_handoffs_do_not_promote_authority(repetitions):
    records = [event("source", 0, "tool.output", evidence={"origin": "untrusted-tool", "instruction": "transfer"})]
    previous = "source"
    for i in range(repetitions):
        identifier = f"copy-{i}"
        records.append(event(identifier, i + 1, ("summary", "retry", "handoff")[i % 3],
                             parent_ids=[previous], evidence={"origin": "untrusted-tool", "instruction": "transfer"}))
        previous = identifier
    records.append(event("execute", repetitions + 1, "action.executed", parent_ids=[previous],
                         expected={"authority_source": "user-grant"}, observed={"authority_source": "untrusted-tool"}))
    report = replay(records)
    assert report["first_provable_divergence"]["event_id"] == "execute"
    assert all(row["status"] == "UNASSESSED" for row in report["timeline"][:-1])
    assert all(row["evidence"]["origin"] == "untrusted-tool" for row in report["timeline"][:-1])
    assert report["confidence_scope"].startswith("STRUCTURAL_ONLY")
    unknown = copy.deepcopy(records)
    unknown[-1].pop("expected")
    uncertain = replay(unknown)
    assert uncertain["first_provable_divergence"] is None
    assert uncertain["reconstruction_status"] == "NO_DIVERGENCE_ESTABLISHED"
    assert all(row["status"] == "UNASSESSED" for row in uncertain["timeline"])
    assert uncertain["evidence_completeness"] == "INCOMPLETE"
    assert uncertain["canonical_sha256"] != report["canonical_sha256"]


def test_later_explicit_grant_is_distinct_from_repeated_suggestion():
    records = [event("source", 0, "tool.output", evidence={"origin": "untrusted-tool"}),
               event("grant", 1, "user.grant", evidence={"origin": "user-grant"}),
               event("execute", 2, "action.executed", parent_ids=["grant"],
                     expected={"authority_source": "user-grant"}, observed={"authority_source": "user-grant"})]
    report = replay(records)
    assert report["first_provable_divergence"] is None
    assert report["timeline"][-1]["status"] == "VALID"
    assert report["expectation_scope"].startswith("CALLER_SUPPLIED_ASSERTIONS")
    assert report["attribution_scope"].startswith("EVIDENCE_LABELS_ONLY")
