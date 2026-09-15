# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow forensic question:

> What exactly happened, where did execution first diverge, and what evidence supports that conclusion?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

Current hardening release: **v0.4.2**.

- See [CHANGELOG.md](CHANGELOG.md) for release history.
- See [SECURITY.md](SECURITY.md) before processing sensitive or untrusted evidence.

## v0.4 — AgenTrust TRACE evidence

Agent Replay can now verify a standalone TRACE v0.2 Trust Record against a caller-supplied trusted issuer key and attach the verified record summary to an incident reconstruction.

Install the optional adapter dependency:

```bash
python -m pip install -e '.[trace]'
```

Verify a TRACE record directly:

```bash
agent-replay verify-trace session.trace.json \
  --trusted-key issuer-public.pem
```

Attach verified TRACE evidence to a reconstruction:

```bash
agent-replay reconstruct \
  examples/refund-750/events.jsonl \
  --trace-record session.trace.json \
  --trace-key issuer-public.pem
```

Machine-readable output includes a `trace_evidence` object bound to the exact TRACE record bytes and caller-supplied trusted key by SHA-256:

```text
TRACE record + SHA-256
    ↓
schema / profile validation
    ↓
signature + freshness verification
    ↓
caller-supplied trusted issuer key + SHA-256
    ↓
Agent Replay incident evidence summary
```

### TRACE trust boundary

Agent Replay does **not** trust the public key embedded in an incoming TRACE record. The issuer key must be supplied independently as PEM or JWK JSON.

The current adapter verifies the standalone TRACE record's schema/profile, cryptographic signature, and freshness through the audited `agentrust-trace` **0.9.1** verifier line (`>=0.9.1,<0.10.0`). It does **not** independently verify:

- hardware attestation evidence,
- transparency-ledger inclusion,
- cMCP RuntimeClaim envelopes,
- or that the incident input is the external transcript committed by `tool_transcript.hash`.

Those distinctions are preserved in the emitted verification scope rather than inferred.

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

Original OTLP provenance is retained, including trace ID, span ID, parent-span relationship, instrumentation scope, exact `startTimeUnixNano`, and OTel status.

An OpenTelemetry `parentSpanId` is ancestry/provenance, not automatically a causal claim. Agent Replay only maps it into canonical causal `parent_ids` when the child span explicitly carries:

```text
agent.replay.causal_parent = true
```

If an OTLP document contains multiple trace IDs, reconstruction fails closed unless one is selected:

```bash
agent-replay reconstruct traces.json --format otel --trace-id <trace-id>
```

This prevents unrelated traces from being merged into one incident.

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

Expected-state values are caller-supplied assertions unless separately bound to authenticated policy evidence. The machine-readable incident therefore includes `expectation_scope`. Likewise, `confidence` is structural confidence only; it does not independently establish truth, identity, or policy provenance, and this limit is stated in `confidence_scope`.

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
Reconstruction: DIVERGENCE_RECONSTRUCTED
Reproducibility: NOT_TESTED
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

Timestamps are normalized to UTC before ordering. Equal-time events are topologically ordered so an evidenced parent cannot be placed after its child. Events without expected-state evidence are labeled `UNASSESSED`, not `VALID`.

Each reconstruction contains:

```text
input_sha256
canonical_sha256
```

The first hashes the exact evidence bytes supplied by the caller, including the original OTLP JSON when `--format otel` is used. The second hashes the normalized canonical representation. When verified TRACE evidence is attached, the TRACE record and trusted key are individually hashed and a supplementary evidence-bundle hash binds those fingerprints to the incident.

## Causality

Agent Replay distinguishes:

```text
ROOT_DIVERGENCE
EXPLICITLY_DOWNSTREAM
TEMPORALLY_DOWNSTREAM
```

A later event is not described as causal merely because it happened later. OpenTelemetry span ancestry is also not promoted to causality unless explicitly asserted by `agent.replay.causal_parent=true`.

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
Engine SHA-256: ...
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

Standalone core and schema-conformance tests:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

Normal runtime use still requires no third-party core dependencies:

```bash
python -m pip install -e .
```

Optional DDC adapter:

```bash
python -m pip install -e ./adapters/ddc
pytest -q adapters/ddc/tests
```

The DDC checkout referenced by `DDC_RADIAL_ROOT` is executable local code and must be treated as trusted.

No hosted infrastructure or GitHub Actions are required.

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
