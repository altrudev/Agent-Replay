from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_replay_service.identity import IdentityError, issue_test_identity_token, verify_test_identity_token
from agent_replay_service.plans import PlanConfig
from agent_replay_service.service import HostedReplayService
from agent_replay_service.store import Entitlement, Store
from agent_replay_service.worker import WorkerError


def make_store(tmp_path):
    store = Store(tmp_path / "control.db")
    store.init()
    return store


def test_verified_email_required_for_internal_access(tmp_path):
    store = make_store(tmp_path)
    store.grant_special_access(email="tester@example.com", role="TESTER")
    unverified = store.get_or_create_account(provider="test", provider_subject="u1", email="tester@example.com", email_verified=False, now=1)
    assert store.resolve_entitlement(account_id=unverified, now=2).plan_id == "free_2026_01"
    verified = store.get_or_create_account(provider="test", provider_subject="u2", email="tester@example.com", email_verified=True, now=1)
    ent = store.resolve_entitlement(account_id=verified, now=2)
    assert ent.plan_id == "internal_2026_01"
    assert ent.role == "TESTER"
    assert ent.plan.replay_limit is None


def test_expired_tester_falls_back_to_normal_plan(tmp_path):
    store = make_store(tmp_path)
    store.grant_special_access(email="tester@example.com", role="TESTER", expires_at=100)
    account = store.get_or_create_account(provider="test", provider_subject="u1", email="tester@example.com", email_verified=True, now=1)
    assert store.resolve_entitlement(account_id=account, now=99).role == "TESTER"
    assert store.resolve_entitlement(account_id=account, now=100).role == "USER"


def test_atomic_reservations_do_not_exceed_plan_limit(tmp_path):
    store = make_store(tmp_path)
    account = store.get_or_create_account(provider="test", provider_subject="u1", email=None, email_verified=False, now=1)
    ent = store.resolve_entitlement(account_id=account, now=2)
    tiny = Entitlement(
        account_id=ent.account_id,
        role=ent.role,
        plan_id="test",
        plan=PlanConfig("test", "Test", 2, 1024, 100, 0, False, False),
    )
    r1 = store.reserve(entitlement=tiny, period_key="p", request_id="a", now=10)
    r2 = store.reserve(entitlement=tiny, period_key="p", request_id="b", now=10)
    with pytest.raises(PermissionError):
        store.reserve(entitlement=tiny, period_key="p", request_id="c", now=10)
    store.commit(reservation_id=r1)
    store.release(reservation_id=r2)
    assert store.usage_status(entitlement=tiny, period_key="p").used == 1


def test_request_id_is_idempotent_and_failure_does_not_count(tmp_path):
    store = make_store(tmp_path)
    account = store.get_or_create_account(provider="test", provider_subject="u1", email=None, email_verified=False, now=1)
    ent = store.resolve_entitlement(account_id=account, now=2)
    service = HostedReplayService(store)
    now = datetime(2026, 9, 17, tzinfo=timezone.utc)

    def fail(**kwargs):
        raise WorkerError("boom")

    failed = service.replay(entitlement=ent, evidence=b"{}\n", now=now, runner=fail)
    assert failed.ok is False
    assert failed.counted is False
    assert failed.usage["used"] == 0

    def succeed(**kwargs):
        return {"schema": "agent-replay.incident.v2"}

    first = service.replay(entitlement=ent, evidence=b"{}\n", now=now, runner=succeed)
    second = service.replay(entitlement=ent, evidence=b"{}\n", now=now, runner=succeed)
    assert first.request_id == second.request_id
    assert second.usage["used"] == 1


def test_signed_test_identity_tokens_reject_tampering():
    token = issue_test_identity_token(secret="secret", subject="abc", email="admin@example.com", email_verified=True, now=100, ttl_seconds=60)
    identity = verify_test_identity_token(token, secret="secret", now=120)
    assert identity.subject == "abc"
    assert identity.email_verified is True
    with pytest.raises(IdentityError):
        verify_test_identity_token(token + "x", secret="secret", now=120)
