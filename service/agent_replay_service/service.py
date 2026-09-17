from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .control import current_free_period_key, usage_payload
from .plain import input_too_large_message
from .store import Entitlement, Store
from .worker import WorkerError, run_replay_subprocess


@dataclass(frozen=True)
class ReplayResponse:
    ok: bool
    request_id: str
    counted: bool
    usage: dict[str, Any]
    result: dict[str, Any] | None = None
    message: str | None = None


class HostedReplayService:
    def __init__(self, store: Store):
        self.store = store

    def replay(
        self,
        *,
        entitlement: Entitlement,
        evidence: bytes,
        requested_operation: str = "replay",
        now: datetime | None = None,
        timeout_seconds: float = 10.0,
        runner=run_replay_subprocess,
    ) -> ReplayResponse:
        current = now or datetime.now(timezone.utc)
        period_key = current_free_period_key(current)
        reset_label = "on the first day of next month"
        request_id = hashlib.sha256(
            b"\0".join([
                entitlement.account_id.encode("utf-8"),
                hashlib.sha256(evidence).hexdigest().encode("ascii"),
                requested_operation.encode("utf-8"),
            ])
        ).hexdigest()
        before = usage_payload(
            self.store,
            entitlement=entitlement,
            period_key=period_key,
            reset_label=reset_label,
        )
        if len(evidence) > entitlement.plan.max_input_bytes:
            return ReplayResponse(
                ok=False,
                request_id=request_id,
                counted=False,
                usage=before,
                message=input_too_large_message(actual_bytes=len(evidence), plan=entitlement.plan),
            )
        try:
            reservation_id = self.store.reserve(
                entitlement=entitlement,
                period_key=period_key,
                request_id=request_id,
            )
        except PermissionError:
            return ReplayResponse(
                ok=False,
                request_id=request_id,
                counted=False,
                usage=before,
                message=before["message"] + (" Upgrade to Pro to continue now." if before["upgrade_available"] else ""),
            )
        try:
            result = runner(evidence=evidence, timeout_seconds=timeout_seconds)
        except WorkerError:
            self.store.release(reservation_id=reservation_id)
            after_failure = usage_payload(
                self.store,
                entitlement=entitlement,
                period_key=period_key,
                reset_label=reset_label,
            )
            return ReplayResponse(
                ok=False,
                request_id=request_id,
                counted=False,
                usage=after_failure,
                message="Agent Replay could not complete this replay. Your usage was not affected.",
            )
        self.store.commit(reservation_id=reservation_id)
        after = usage_payload(
            self.store,
            entitlement=entitlement,
            period_key=period_key,
            reset_label=reset_label,
        )
        return ReplayResponse(
            ok=True,
            request_id=request_id,
            counted=True,
            usage=after,
            result=result,
        )
