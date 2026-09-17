# Hosted Agent Replay service — implementation contract

Status: v0.1 hosted-service baseline.

## Service layout

```text
ChatGPT / test harness
        |
        v
identity adapter
        |
        v
control plane
  - account
  - plan
  - usage
  - admin/tester role
        |
        v
ephemeral replay worker
  - Agent Replay core
  - bounded runtime
  - no billing/account metadata
```

## User-facing states

Primary UI stays plain and compact:

- `Agent Replay · Off`
- `Agent Replay · This request · 12 left`
- `Agent Replay · Preferred on`
- `Agent Replay · Limit reached`
- `Agent Replay · Temporarily unavailable`

Technical codes/version details belong under **Details**.

## Usage accounting

A replay is counted only when processing completes successfully.

```text
RESERVE
   +-- success --> COMMIT
   +-- failure --> RELEASE
   +-- worker lost --> reservation expiry --> RELEASE
```

Repeated requests with the same account, evidence digest and operation must not consume a second quota unit.

ADMIN/TESTER users have no commercial replay-count limit, but usage is still measured and all technical limits remain active.

## Identity

Email text is not identity. Internal access requires a verified platform/OAuth identity, a verified email claim, and an active allowlist entry. The local harness uses a short-lived HMAC token only to simulate this boundary.

## Data boundary

SQLite may contain account IDs, provider subjects, verified email, plan/version, usage counters, reservation IDs, future Stripe event IDs, and admin audit metadata.

SQLite must never contain prompts, conversations, event bodies, expected/observed values, tool output, replay findings or uploaded evidence.

## Plans

Plan definitions are versioned (`free_2026_01`, `pro_2026_01`, etc.) so limits can evolve without rewriting historical accounts. Correctness is identical across plans; paid plans buy capacity/features, not a different forensic truth.

## Current VPS deployment

Run the service as a separate Linux identity/resource slice from DSR. Initial internal bind: `127.0.0.1:8791`. DSR and Agent Replay may share the machine but not users, directories, secrets or service permissions.

Production workers should additionally receive OS-level CPU, memory, filesystem and network restrictions. The Python subprocess boundary is the application seam, not a substitute for OS isolation.

## Release policy

Never `git pull` over the running service. Build a candidate from an exact release, run tests/frozen replay corpus, start it beside the current service, then switch traffic. Keep the previous version available for rollback.

## ChatGPT adapter

The public ChatGPT integration remains thin: `get_my_usage`, `get_my_plan`, `replay_incident`, and preference controls where the platform allows them. It must not duplicate forensic logic from the core.
