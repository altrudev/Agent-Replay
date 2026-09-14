# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow question:

> What exactly happened, where did execution first diverge, and what evidence proves it?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

## Core principle

Agent Replay reconstructs incidents from evidence left behind by agent execution.

Inputs can include:

- JSONL event streams
- OpenTelemetry traces
- MCP/tool-call events
- HTTP/API logs
- browser events
- approval events

The core package has **zero dependency on DDC, DSR, DDCRE, ddcal.ca, or any Altru.dev infrastructure**.

## Quick start

```bash
python -m pip install -e .
agent-replay reconstruct examples/refund-750/events.jsonl
```

The included incident reconstructs a refund-agent failure where the authorized limit was $200 but $750 was issued. The first provable divergence is the retrieval of policy `v17` instead of `v19`.

## Optional DDC adapter

DDC support is deliberately isolated as a separate package:

```bash
python -m pip install -e ./adapters/ddc
export AGENT_REPLAY_DDC_CMD='python /path/to/ddc_agent_replay_adapter.py'
agent-replay-ddc verify examples/refund-750/events.jsonl
```

Deleting `adapters/ddc/` does not affect Agent Replay.

## Product boundary

```
Evidence bundle
    ↓
Normalization
    ↓
Ordered event model
    ↓
Expected vs observed transitions
    ↓
First provable divergence
    ↓
Incident reconstruction
    ↓
Evidence hash + reproducibility result
```

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
