# Agent Replay hosted service (v0.1)

This package is the hosted control plane + bounded replay launcher for Agent Replay.

It is deliberately separate from the standalone forensic core.

## Frozen boundary

- Identity, plans, billing and roles determine what a user may consume.
- Replay evidence determines what Agent Replay concludes.
- Account/billing data must not enter replay workers.
- Replay evidence must not be stored in the control-plane database.
- `ADMIN` / `TESTER` remove commercial quota only. They do not bypass technical safety limits.

## Implemented

- versioned Free / Pro / Internal plans
- verified-identity boundary for admin/tester access
- SQLite account, entitlement and usage control plane
- atomic quota reservations
- retry-safe request IDs
- failure-does-not-count semantics
- plain-language limit messages
- short-lived replay subprocess entry point
- local HTTP test harness for users without ChatGPT MCP access
- admin CLI for adding/removing tester/admin email addresses

## Local test harness

```bash
cd service
python -m pip install -e '.[dev]'
python -m pytest -q

export PYTHONPATH="../src:$PWD"
export AGENT_REPLAY_TEST_IDENTITY_SECRET="replace-me"
python -m agent_replay_service.admin_cli --db ./control.db init-db
python -m agent_replay_service.dev_server
```

The server listens on `127.0.0.1:8791` by default.

Production identity will replace the test HMAC-token adapter with verified ChatGPT/OAuth identity. The downstream account/entitlement interface remains unchanged.

## Admin and tester access

Never hardcode privileged email addresses in application logic.

```bash
python -m agent_replay_service.admin_cli --db ./control.db grant admin@example.com ADMIN
python -m agent_replay_service.admin_cli --db ./control.db grant beta@example.com TESTER --expires-at 1790000000
python -m agent_replay_service.admin_cli --db ./control.db revoke beta@example.com
```

An allowlisted address receives internal access only after the identity provider has verified that email address.
