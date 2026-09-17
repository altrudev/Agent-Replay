from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlanConfig:
    plan_id: str
    label: str
    replay_limit: int | None
    max_input_bytes: int
    max_events: int
    priority: int
    signed_bundle: bool
    upgrade_available: bool


PLANS: dict[str, PlanConfig] = {
    "free_2026_01": PlanConfig(
        plan_id="free_2026_01",
        label="Free",
        replay_limit=20,
        max_input_bytes=10 * 1024 * 1024,
        max_events=25_000,
        priority=0,
        signed_bundle=False,
        upgrade_available=True,
    ),
    "pro_2026_01": PlanConfig(
        plan_id="pro_2026_01",
        label="Pro",
        replay_limit=500,
        max_input_bytes=50 * 1024 * 1024,
        max_events=100_000,
        priority=10,
        signed_bundle=True,
        upgrade_available=False,
    ),
    "internal_2026_01": PlanConfig(
        plan_id="internal_2026_01",
        label="Internal access",
        replay_limit=None,
        max_input_bytes=50 * 1024 * 1024,
        max_events=100_000,
        priority=20,
        signed_bundle=True,
        upgrade_available=False,
    ),
}


def get_plan(plan_id: str) -> PlanConfig:
    try:
        return PLANS[plan_id]
    except KeyError as exc:
        raise ValueError(f"unknown plan_id: {plan_id}") from exc
