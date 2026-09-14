# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow forensic question:

> What exactly happened, where did execution first diverge, and what evidence supports that conclusion?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

## One-command demo

```bash
python -m pip install -e .
agent-replay reconstruct examples/refund-750/events.jsonl
```

Example result:

```text
AGENT REPLAY INCIDENT
Events: 5
Reproducibility: CONFIRMED
Confidence: HIGH

FIRST PROVABLE DIVERGENCE
2026-09-14T12:04:25Z  evt_019  policy.read
Actor: refund-agent
- policy_version: expected=v19 observed=v17

CAUSAL / TEMPORAL CHAIN
- evt_019 policy.read       [ROOT_DIVERGENCE]
- evt_023 refund.generated  [EXPLICITLY_DOWNSTREAM]
- evt_024 approval.check    [EXPLICITLY_DOWNSTREAM]
- evt_025 payment.refund    [EXPLICITLY_DOWNSTREAM]

ATTRIBUTION
- refund-agent: PRIMARY
- approval-gate: CONTRIBUTING
- payment-api: CONTRIBUTING
```

For the complete machine-readable incident document:

```bash
agent-replay reconstruct examples/refund-750/events.jsonl --json
```

## What v0.2 does

Agent Replay now provides:

- deterministic JSONL normalization
- canonical event representation
- expected-versus-observed divergence detection
- earliest provable divergence identification
- explicit parent/ancestor correlation
- temporal fallback when causality is not evidenced
- deterministic attribution roles
- evidence-bundle SHA-256
- human-readable and JSON reports
- a versioned incident schema

Agent Replay deliberately distinguishes:

```text
EXPLICITLY_DOWNSTREAM
```

from:

```text
TEMPORALLY_DOWNSTREAM
```

A later event is **not** described as causal merely because it happened later.

## Canonical input

Each JSONL line is an event:

```json
{
  "event_id": "evt_023",
  "timestamp": "2026-09-14T12:04:27Z",
  "actor": "refund-agent",
  "kind": "refund.generated",
  "parent_ids": ["evt_019"],
  "observed": {"refund_amount": 750},
  "expected": {"refund_amount": 200},
  "evidence": {"source": "tool.jsonl"}
}
```

`parent_ids` are optional. Without explicit provenance links, Agent Replay preserves temporal ordering but does not manufacture a causal edge.

## Incident output

The v0.2 machine-readable contract is:

```text
agent-replay.incident.v2
```

JSON Schema:

```text
schemas/incident-v2.schema.json
```

Attribution roles currently use:

- `PRIMARY` — actor owns the earliest provable divergence
- `CONTRIBUTING` — actor owns an explicitly downstream divergent event
- `DOWNSTREAM` — later divergence exists without an evidenced causal edge

These labels describe the evidence graph. They are not a legal or organizational assignment of blame.

## Inputs

The v0.2 core consumes canonical JSONL directly.

Adapters for formats such as OpenTelemetry, MCP logs, HTTP/API logs, browser events, and approval systems can normalize those sources into the canonical event model without changing the reconstruction engine.

## Standalone by design

The core package has **zero dependency on DDC, DSR, DDCRE, ddcal.ca, or any Altru.dev infrastructure**.

```text
raw evidence
    ↓
normalization
    ↓
canonical events
    ↓
divergence analysis
    ↓
causal / temporal reconstruction
    ↓
attribution
    ↓
incident report
```

A clean machine only needs Python and this repository to run Agent Replay.

## Optional DDC adapter

DDC support is isolated as a separate installable package:

```bash
python -m pip install -e ./adapters/ddc
export AGENT_REPLAY_DDC_CMD='python /path/to/ddc_agent_replay_adapter.py'
agent-replay-ddc verify examples/refund-750/events.jsonl
```

The adapter sends the reconstructed incident to a configured DDC command over a narrow JSON stdin/stdout boundary.

Deleting `adapters/ddc/` does not affect Agent Replay.

## Development

```bash
python -m pip install -e .
python -m pip install pytest
pytest -q
```

No GitHub Actions or hosted infrastructure are required.

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
