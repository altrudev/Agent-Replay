from __future__ import annotations

from .plans import PlanConfig


def usage_message(*, plan: PlanConfig, used: int, remaining: int | None, reset_label: str) -> str:
    if plan.replay_limit is None:
        return f"{plan.label}. Unlimited replays for testing. Usage is still measured."
    if remaining is None:
        remaining = max(plan.replay_limit - used, 0)
    if remaining <= 0:
        return (
            f"You've used all {plan.replay_limit} replays included with your {plan.label} plan. "
            f"Your allowance resets {reset_label}."
        )
    if remaining == 1:
        return f"You have 1 replay left on your {plan.label} plan. Your allowance resets {reset_label}."
    return f"You have {remaining} replays left on your {plan.label} plan. Your allowance resets {reset_label}."


def input_too_large_message(*, actual_bytes: int, plan: PlanConfig) -> str:
    actual_mb = actual_bytes / (1024 * 1024)
    limit_mb = plan.max_input_bytes / (1024 * 1024)
    return (
        f"This replay is too large for your {plan.label} plan. "
        f"Your file is {actual_mb:.1f} MB and your plan allows up to {limit_mb:.0f} MB. "
        "Upload a smaller file" + (" or upgrade to Pro." if plan.upgrade_available else ".")
    )


def busy_message() -> str:
    return "Agent Replay is busy right now. Your replay was not counted. Try again shortly."


def unavailable_message() -> str:
    return "Agent Replay is temporarily unavailable. Your replay was not counted. Please try again."
