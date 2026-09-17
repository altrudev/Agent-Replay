from __future__ import annotations

import argparse
import os

from .store import Store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-replay-service-admin")
    parser.add_argument("--db", default=os.environ.get("AGENT_REPLAY_CONTROL_DB", "agent-replay-control.db"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    grant = sub.add_parser("grant")
    grant.add_argument("email")
    grant.add_argument("role", choices=["ADMIN", "TESTER"])
    grant.add_argument("--expires-at", type=int)
    grant.add_argument("--notes")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("email")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    store.init()
    if args.command == "init-db":
        print(f"initialized {args.db}")
        return 0
    if args.command == "grant":
        store.grant_special_access(email=args.email, role=args.role, expires_at=args.expires_at, notes=args.notes)
        print(f"granted {args.role} to {args.email.lower()}")
        return 0
    if args.command == "revoke":
        store.revoke_special_access(email=args.email)
        print(f"revoked internal access for {args.email.lower()}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
