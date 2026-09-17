from __future__ import annotations

import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .plans import PlanConfig, get_plan


@dataclass(frozen=True)
class Entitlement:
    account_id: str
    role: str
    plan_id: str
    plan: PlanConfig


@dataclass(frozen=True)
class UsageStatus:
    account_id: str
    plan_id: str
    used: int
    limit: int | None
    remaining: int | None
    period_key: str


class Store:
    """Small control-plane store. Replay evidence never belongs here."""

    def __init__(self, path: str | Path):
        self.path = str(path)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    provider_subject TEXT NOT NULL,
                    email TEXT,
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    UNIQUE(provider, provider_subject)
                );
                CREATE TABLE IF NOT EXISTS special_access (
                    email TEXT PRIMARY KEY,
                    role TEXT NOT NULL CHECK(role IN ('ADMIN','TESTER')),
                    active INTEGER NOT NULL DEFAULT 1,
                    expires_at INTEGER,
                    notes TEXT
                );
                CREATE TABLE IF NOT EXISTS entitlements (
                    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
                    plan_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    period_end INTEGER,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS usage_periods (
                    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                    period_key TEXT NOT NULL,
                    committed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(account_id, period_key)
                );
                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                    period_key TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('RESERVED','COMMITTED','RELEASED')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    UNIQUE(account_id, request_id)
                );
                CREATE TABLE IF NOT EXISTS processed_webhooks (
                    event_id TEXT PRIMARY KEY,
                    processed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_account_id TEXT,
                    action TEXT NOT NULL,
                    target_account_id TEXT,
                    details TEXT,
                    created_at INTEGER NOT NULL
                );
                """
            )

    def get_or_create_account(self, *, provider: str, provider_subject: str, email: str | None,
                              email_verified: bool, now: int | None = None) -> str:
        current = int(time.time() if now is None else now)
        normalized_email = email.lower() if email else None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT account_id FROM accounts WHERE provider=? AND provider_subject=?",
                (provider, provider_subject),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE accounts SET email=?, email_verified=? WHERE account_id=?",
                    (normalized_email, int(email_verified), row["account_id"]),
                )
                return str(row["account_id"])
            account_id = f"acct_{uuid.uuid4().hex}"
            conn.execute(
                "INSERT INTO accounts(account_id,provider,provider_subject,email,email_verified,created_at) VALUES (?,?,?,?,?,?)",
                (account_id, provider, provider_subject, normalized_email, int(email_verified), current),
            )
            conn.execute(
                "INSERT INTO entitlements(account_id,plan_id,state,period_end,updated_at) VALUES (?,'free_2026_01','ACTIVE',NULL,?)",
                (account_id, current),
            )
            return account_id

    def grant_special_access(self, *, email: str, role: str, expires_at: int | None = None,
                             notes: str | None = None) -> None:
        if role not in {"ADMIN", "TESTER"}:
            raise ValueError("role must be ADMIN or TESTER")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO special_access(email,role,active,expires_at,notes)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(email) DO UPDATE SET role=excluded.role,active=1,
                    expires_at=excluded.expires_at,notes=excluded.notes
                """,
                (email.strip().lower(), role, expires_at, notes),
            )

    def revoke_special_access(self, *, email: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE special_access SET active=0 WHERE email=?", (email.strip().lower(),))

    def resolve_entitlement(self, *, account_id: str, now: int | None = None) -> Entitlement:
        current = int(time.time() if now is None else now)
        with self.connect() as conn:
            account = conn.execute(
                "SELECT email,email_verified FROM accounts WHERE account_id=?", (account_id,)
            ).fetchone()
            if not account:
                raise KeyError("account not found")
            if account["email"] and account["email_verified"]:
                special = conn.execute(
                    "SELECT role,expires_at FROM special_access WHERE email=? AND active=1",
                    (account["email"],),
                ).fetchone()
                if special and (special["expires_at"] is None or int(special["expires_at"]) > current):
                    return Entitlement(account_id, str(special["role"]), "internal_2026_01", get_plan("internal_2026_01"))
            row = conn.execute(
                "SELECT plan_id,state,period_end FROM entitlements WHERE account_id=?", (account_id,)
            ).fetchone()
            if not row:
                raise KeyError("entitlement not found")
            plan_id = str(row["plan_id"])
            if str(row["state"]) not in {"ACTIVE", "GRACE", "CANCEL_AT_END"}:
                plan_id = "free_2026_01"
            elif row["period_end"] is not None and int(row["period_end"]) <= current:
                plan_id = "free_2026_01"
            return Entitlement(account_id, "USER", plan_id, get_plan(plan_id))

    def set_plan(self, *, account_id: str, plan_id: str, state: str = "ACTIVE",
                 period_end: int | None = None, now: int | None = None) -> None:
        get_plan(plan_id)
        current = int(time.time() if now is None else now)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO entitlements(account_id,plan_id,state,period_end,updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(account_id) DO UPDATE SET plan_id=excluded.plan_id,state=excluded.state,
                    period_end=excluded.period_end,updated_at=excluded.updated_at
                """,
                (account_id, plan_id, state, period_end, current),
            )

    def usage_status(self, *, entitlement: Entitlement, period_key: str) -> UsageStatus:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT committed FROM usage_periods WHERE account_id=? AND period_key=?",
                (entitlement.account_id, period_key),
            ).fetchone()
            used = int(row["committed"]) if row else 0
        limit = entitlement.plan.replay_limit
        remaining = None if limit is None else max(limit - used, 0)
        return UsageStatus(entitlement.account_id, entitlement.plan_id, used, limit, remaining, period_key)

    def reserve(self, *, entitlement: Entitlement, period_key: str, request_id: str,
                ttl_seconds: int = 60, now: int | None = None) -> str:
        current = int(time.time() if now is None else now)
        self.expire_reservations(now=current)
        reservation_id = f"rsv_{uuid.uuid4().hex}"
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT reservation_id,state FROM reservations WHERE account_id=? AND request_id=?",
                (entitlement.account_id, request_id),
            ).fetchone()
            if existing:
                if existing["state"] in {"COMMITTED", "RESERVED"}:
                    return str(existing["reservation_id"])
                conn.execute(
                    "UPDATE reservations SET state='RESERVED',created_at=?,expires_at=? WHERE reservation_id=?",
                    (current, current + ttl_seconds, existing["reservation_id"]),
                )
                return str(existing["reservation_id"])
            row = conn.execute(
                "SELECT committed FROM usage_periods WHERE account_id=? AND period_key=?",
                (entitlement.account_id, period_key),
            ).fetchone()
            committed = int(row["committed"]) if row else 0
            reserved = int(conn.execute(
                "SELECT COUNT(*) AS c FROM reservations WHERE account_id=? AND period_key=? AND state='RESERVED'",
                (entitlement.account_id, period_key),
            ).fetchone()["c"])
            limit = entitlement.plan.replay_limit
            if limit is not None and committed + reserved >= limit:
                raise PermissionError("replay limit reached")
            conn.execute(
                "INSERT INTO reservations(reservation_id,account_id,period_key,request_id,state,created_at,expires_at) VALUES (?,?,?,?,'RESERVED',?,?)",
                (reservation_id, entitlement.account_id, period_key, request_id, current, current + ttl_seconds),
            )
        return reservation_id

    def commit(self, *, reservation_id: str) -> None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT account_id,period_key,state FROM reservations WHERE reservation_id=?", (reservation_id,)
            ).fetchone()
            if not row:
                raise KeyError("reservation not found")
            if row["state"] == "COMMITTED":
                return
            if row["state"] != "RESERVED":
                raise ValueError("reservation is not active")
            conn.execute(
                """
                INSERT INTO usage_periods(account_id,period_key,committed) VALUES (?,?,1)
                ON CONFLICT(account_id,period_key) DO UPDATE SET committed=committed+1
                """,
                (row["account_id"], row["period_key"]),
            )
            conn.execute("UPDATE reservations SET state='COMMITTED' WHERE reservation_id=?", (reservation_id,))

    def release(self, *, reservation_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE reservations SET state='RELEASED' WHERE reservation_id=? AND state='RESERVED'",
                (reservation_id,),
            )

    def expire_reservations(self, *, now: int | None = None) -> int:
        current = int(time.time() if now is None else now)
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE reservations SET state='RELEASED' WHERE state='RESERVED' AND expires_at<=?",
                (current,),
            )
            return int(cur.rowcount)
