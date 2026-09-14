# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow forensic question:

> What exactly happened, where did execution first diverge, and what evidence supports that conclusion?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

## v0.3 — OpenTelemetry ingestion

Agent Replay can now reconstruct directly from OpenTelemetry OTLP JSON.

```bash
python -m pip install -e .

agent-replay reconstruct   examples/refund-750/otel.json   --format otel
```

That performs:

```text
OTLP JSON
   ↓
OpenTelemetry normalization
   ↓
Agent Replay canonical events
   ↓
temporal + provenance validation
   ↓
incident reconstruction
   ↓
first provable divergence
   ↓
causal / temporal chain
   ↓
evidence attribution
```

The same input can be normalized explicitly for inspection:

```bash
agent-replay ingest otel   examples/refund-750/otel.json   -o canonical.jsonl

agent-replay reconstruct canonical.jsonl
```

Machine-readable incident output:

```bash
agent-replay reconstruct   examples/refund-750/otel.json   --format otel   --json
```

## OpenTelemetry evidence convention

Generic OpenTelemetry establishes chronology and parent/span provenance, but it does not inherently say what **should** have happened.

Agent Replay therefore supports explicit expected/observed attributes:

```text
agent.replay.expected.<field>
agent.replay.observed.<field>
```

Example:

```json
{
  "key": "agent.replay.expected.refund_amount",
  "value": {"intValue": "200"}
}
```

and:

```json
{
  "key": "agent.replay.observed.refund_amount",
  "value": {"intValue": "750"}
}
```

Optional actor labels are read from, in priority order:

```text
agent.name
gen_ai.agent.name
service.name
```

The original OTLP provenance is retained, including:

- trace ID
- span ID
- parent span relationship
- instrumentation scope name/version
- OpenTelemetry status code/message

### Evidence sufficiency

Agent Replay does **not** interpret the absence of expected-state evidence as proof that execution was correct.

Every incident includes:

```text
Expectation coverage: COMPLETE | PARTIAL | NO_EXPECTATIONS | NO_EVENTS
```

For ordinary telemetry with no Agent Replay expectation attributes:

```text
No provable divergence found.
No divergence can be established for events lacking expected-state evidence.
```

This is deliberate. The engine does not manufacture normative claims from telemetry.

## Example incident

The repository includes the same refund incident in two forms:

```text
examples/refund-750/events.jsonl   canonical Agent Replay
examples/refund-750/otel.json      OpenTelemetry OTLP JSON
```

The expected reconstruction is:

```text
AGENT REPLAY INCIDENT

Events: 5
Expectation coverage: COMPLETE (5/5)
Reproducibility: CONFIRMED
Confidence: HIGH

TIMELINE
task.accepted       VALID
policy.read         DIVERGENT
refund.generated    DIVERGENT
approval.check      DIVERGENT
payment.refund      DIVERGENT

FIRST PROVABLE DIVERGENCE
policy.read

policy_version
expected=v19
observed=v17

CAUSAL CHAIN
policy.read
    ↓
refund.generated
    ↓
approval.check
    ↓
payment.refund
```

## Forensic integrity

Agent Replay validates the evidence graph before reconstruction.

It fails closed on:

- invalid or timezone-less timestamps
- duplicate event IDs
- unknown parents
- duplicate parent IDs
- self-parenting
- parent events occurring after their child
- causal graph cycles

Timestamps are normalized to UTC before ordering.

Each reconstruction includes two hashes:

```text
input_sha256       exact supplied evidence bytes
canonical_sha256   normalized canonical incident representation
```

## Causality

Agent Replay distinguishes:

```text
ROOT_DIVERGENCE
EXPLICITLY_DOWNSTREAM
TEMPORALLY_DOWNSTREAM
```

A later event is **not** described as causal merely because it happened later.

Explicit causality comes from evidence relationships such as canonical `parent_ids` or OpenTelemetry `parentSpanId`.

## Attribution

Current roles are:

- `PRIMARY` — actor label owns the earliest provable divergence
- `CONTRIBUTING` — actor label owns an explicitly downstream divergent event
- `DOWNSTREAM` — actor label owns a later divergence without an evidenced causal edge

Actor identities are **evidence labels only**. Agent Replay does not independently authenticate the entity behind an actor string.

These roles are forensic classifications, not legal or organizational assignments of blame.

## Canonical input

Canonical JSONL remains a first-class format:

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

## Machine-readable incident contract

Current incident contract:

```text
agent-replay.incident.v2
```

Schema:

```text
schemas/incident-v2.schema.json
```

## Optional DDC Radial analysis

Agent Replay does not require DDC.

The optional package under `adapters/ddc/` maps a completed Agent Replay incident into the private DDC Radial Frequency engine.

```bash
python -m pip install -e ./adapters/ddc

export DDC_RADIAL_ROOT=/path/to/ddc

agent-replay reconstruct   examples/refund-750/otel.json   --format otel   --json   | agent-replay-ddc-radial
```

DDC Radial findings remain:

```text
authoritative = false
disposition = CANDIDATE
```

They are structural fault hypotheses and falsification proposals, not Agent Replay findings, blame assignments, or execution authority.

Deleting `adapters/ddc/` leaves Agent Replay fully functional.

## Standalone boundary

The core package has **zero dependency on DDC, DSR, DDCRE, ddcal.ca, or any Altru.dev infrastructure**.

A clean machine only needs Python and this repository.

## Development

```bash
python -m pip install -e .
python -m pip install pytest
pytest -q
```

No hosted infrastructure or GitHub Actions are required.

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
