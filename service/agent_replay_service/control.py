from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from .identity import VerifiedIdentity
from .plain import usage_message
from .store import Entitlement, Store


def current_free_period_key(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    return f"free:{current.year:04d}-{current.month:02d}"


def resolve_account(store: Store, *, identity: VerifiedIdentity, provider: str = "test-harness") -> tuple[str, Entitlement]:
    account_id = store.get_or_create_account(
        provider=provider,
        provider_subject=identity.subject,
        email=identity.email,
        email_verified=identity.email_verified,
    )
    return account_id, store.resolve_entitlement(account_id=account_id)


def usage_payload(store: Store, *, entitlement: Entitlement, period_key: str, reset_label: str) -> dict:
    status = store.usage_status(entitlement=entitlement, period_key=period_key)
    return {
        "plan": entitlement.plan.label,
        "plan_id": entitlement.plan_id,
        "role": entitlement.role,
        "used": status.used,
        "limit": status.limit,
        "remaining": status.remaining,
        "period_key": status.period_key,
        "max_input_bytes": entitlement.plan.max_input_bytes,
        "max_events": entitlement.plan.max_events,
        "features": {
            "signed_bundle": entitlement.plan.signed_bundle,
            "priority_processing": entitlement.plan.priority > 0,
        },
        "upgrade_available": entitlement.plan.upgrade_available,
        "message": usage_message(
            plan=entitlement.plan,
            used=status.used,
            remaining=status.remaining,
            reset_label=reset_label,
        ),
    }


def public_entitlement(entitlement: Entitlement) -> dict:
    data = asdict(entitlement.plan)
    data["role"] = entitlement.role
    return data
