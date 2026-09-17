from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .control import current_free_period_key, resolve_account, usage_payload
from .identity import IdentityError, verify_test_identity_token
from .service import HostedReplayService
from .store import Store


MAX_HTTP_BODY = 55 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentReplayDev/0.1"

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _identity(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise IdentityError("sign in required")
        return verify_test_identity_token(auth[7:], secret=self.server.identity_secret)

    def _account(self):
        identity = self._identity()
        return resolve_account(self.server.store, identity=identity, provider="test-harness")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            return self._json(200, {
                "ok": True,
                "service_version": "0.1.0",
                "processing_mode": "LOCAL_TEST_HARNESS",
                "evidence_retained": False,
            })
        if path == "/v1/usage":
            try:
                _, entitlement = self._account()
            except (IdentityError, KeyError) as exc:
                return self._json(401, {"ok": False, "message": str(exc)})
            now = datetime.now(timezone.utc)
            payload = usage_payload(
                self.server.store,
                entitlement=entitlement,
                period_key=current_free_period_key(now),
                reset_label="on the first day of next month",
            )
            return self._json(200, {"ok": True, "usage": payload})
        return self._json(404, {"ok": False, "message": "Not found."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self._json(400, {"ok": False, "message": "Invalid request size."})
        if length < 0 or length > MAX_HTTP_BODY:
            return self._json(413, {"ok": False, "message": "This file is too large to send to Agent Replay."})
        body = self.rfile.read(length)

        if path == "/v1/replay":
            try:
                _, entitlement = self._account()
            except (IdentityError, KeyError) as exc:
                return self._json(401, {"ok": False, "message": str(exc)})
            response = self.server.replay_service.replay(entitlement=entitlement, evidence=body)
            return self._json(200 if response.ok else 400, asdict(response))

        if path == "/v1/admin/testers":
            try:
                _, entitlement = self._account()
            except (IdentityError, KeyError) as exc:
                return self._json(401, {"ok": False, "message": str(exc)})
            if entitlement.role != "ADMIN":
                return self._json(403, {"ok": False, "message": "Administrator access is required."})
            try:
                data = json.loads(body.decode("utf-8"))
                email = str(data["email"]).strip().lower()
                role = str(data.get("role", "TESTER")).upper()
                expires_at = data.get("expires_at")
                if expires_at is not None:
                    expires_at = int(expires_at)
                self.server.store.grant_special_access(
                    email=email,
                    role=role,
                    expires_at=expires_at,
                    notes="granted from test admin API",
                )
            except Exception:
                return self._json(400, {"ok": False, "message": "Check the tester email and try again."})
            return self._json(200, {"ok": True, "message": f"{role.title()} access enabled for {email}."})

        return self._json(404, {"ok": False, "message": "Not found."})

    def log_message(self, format: str, *args) -> None:
        super().log_message(format, *args)


class Server(ThreadingHTTPServer):
    def __init__(self, address, handler, *, store: Store, identity_secret: str):
        super().__init__(address, handler)
        self.store = store
        self.identity_secret = identity_secret
        self.replay_service = HostedReplayService(store)


def main() -> int:
    host = os.environ.get("AGENT_REPLAY_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENT_REPLAY_PORT", "8791"))
    db_path = os.environ.get("AGENT_REPLAY_CONTROL_DB", "agent-replay-control.db")
    secret = os.environ.get("AGENT_REPLAY_TEST_IDENTITY_SECRET")
    if not secret:
        raise SystemExit("AGENT_REPLAY_TEST_IDENTITY_SECRET is required for the test harness")
    store = Store(db_path)
    store.init()
    server = Server((host, port), Handler, store=store, identity_secret=secret)
    print(f"Agent Replay test service listening on http://{host}:{port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
