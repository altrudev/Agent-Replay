# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow forensic question:

> What exactly happened, where did execution first diverge, and what evidence supports that conclusion?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

## v0.3 — OpenTelemetry ingestion

Agent Replay can reconstruct directly from OpenTelemetry OTLP JSON.

```bash
python -m pip install -e .

agent-replay reconstruct \
  examples/refund-750/otel.json \
  --format otel
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

Explicit normalization is also available:

```bash
agent-replay ingest otel \
  examples/refund-750/otel.json \
  -o canonical.jsonl

agent-replay reconstruct canonical.jsonl
```

Machine-readable output:

```bash
agent-replay reconstruct \
  examples/refund-750/otel.json \
  --format otel \
  --json
```

## OpenTelemetry evidence convention

Generic OpenTelemetry establishes chronology and parent/span provenance, but it does not inherently say what **should** have happened.

Agent Replay therefore supports:

```text
agent.replay.expected.<field>
agent.replay.observed.<field>
```

Example:

```json
{"key":"agent.replay.expected.refund_amount","value":{"intValue":"200"}}
```

```json
{"key":"agent.replay.observed.refund_amount","value":{"intValue":"750"}}
```

Optional actor labels are read from, in priority order:

```text
agent.name
gen_ai.agent.name
service.name
```

Original OTLP provenance is retained, including trace ID, span ID, parent relationship, instrumentation scope, and OTel status.

### Evidence sufficiency

Agent Replay does **not** interpret missing expectations as proof of correctness.

Each incident reports:

```text
Expectation coverage: COMPLETE | PARTIAL | NO_EXPECTATIONS | NO_EVENTS
```

When normative evidence is absent:

```text
No provable divergence found.
No divergence can be established for events lacking expected-state evidence.
```

## Example incident

The included refund incident exists in both formats:

```text
examples/refund-750/events.jsonl
examples/refund-750/otel.json
```

Expected reconstruction:

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
```

## Forensic integrity

Agent Replay fails closed on invalid or timezone-less timestamps, duplicate event IDs, unknown or duplicate parents, self-parenting, future-parent edges, and causal cycles.

Timestamps are normalized to UTC before ordering.

Each reconstruction contains:

```text
input_sha256
canonical_sha256
```

The first hashes the exact supplied evidence bytes. The second hashes the normalized canonical representation.

## Causality

Agent Replay distinguishes:

```text
ROOT_DIVERGENCE
EXPLICITLY_DOWNSTREAM
TEMPORALLY_DOWNSTREAM
```

A later event is not described as causal merely because it happened later.

## Attribution

Current roles are:

- `PRIMARY` — actor label owns the earliest provable divergence
- `CONTRIBUTING` — actor label owns an explicitly downstream divergent event
- `DOWNSTREAM` — later divergent evidence exists without an evidenced causal edge

Actor identities are evidence labels only. Agent Replay does not independently authenticate the entity behind an actor string.

## Optional DDC Radial review

Agent Replay remains fully standalone. DDC is an optional second-order review layer.

Install it separately:

```bash
python -m pip install -e ./adapters/ddc
export DDC_RADIAL_ROOT=/path/to/ddc
```

### One-command review

For OTLP input:

```bash
agent-replay-ddc review \
  examples/refund-750/otel.json \
  --format otel
```

That prints the normal Agent Replay incident followed by a concise DDC Radial appendix:

```text
DDC RADIAL REVIEW
Engine: ddc-radial-frequency/1.0
Candidates: ...

1. Unsafe retry / duplicate effect
   Score: ...
   Subjects:
     - approval.check (...)
     - payment.refund (...)
   Why: ...
   Falsification: ...

Note: DDC Radial findings are non-authoritative CANDIDATE hypotheses.
```

Full machine-readable combined output:

```bash
agent-replay-ddc review \
  examples/refund-750/otel.json \
  --format otel \
  --json
```

The envelope schema is:

```text
agent-replay.ddc-review.v1
```

You can still run Radial directly over incident JSON:

```bash
agent-replay reconstruct \
  examples/refund-750/otel.json \
  --format otel \
  --json \
  | agent-replay-ddc-radial
```

Use `--json` on the Radial command for full feature vectors:

```bash
... | agent-replay-ddc-radial --json
```

DDC Radial findings remain:

```text
authoritative = false
disposition = CANDIDATE
```

They are structural fault hypotheses and falsification proposals, not Agent Replay findings, blame assignments, or execution authority.

Deleting `adapters/ddc/` leaves Agent Replay fully functional.

## Machine-readable incident contract

Current incident contract:

```text
agent-replay.incident.v2
```

Schema:

```text
schemas/incident-v2.schema.json
```

## Development

Standalone core:

```bash
python -m pip install -e .
python -m pip install pytest
pytest -q
```

Optional DDC adapter:

```bash
python -m pip install -e ./adapters/ddc
pytest -q adapters/ddc/tests
```

No hosted infrastructure or GitHub Actions are required.

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
