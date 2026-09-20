# Agent Replay

**Standalone incident reconstruction for AI-agent executions.**

Agent Replay answers a narrow forensic question:

> What exactly happened, where did execution first diverge, and what evidence supports that conclusion?

It is **not** an observability platform, agent runtime, policy engine, or monitoring service.

Current hardening line: **v0.6.0**.

- See [CHANGELOG.md](CHANGELOG.md) for release history.
- See [SECURITY.md](SECURITY.md) before processing sensitive or untrusted evidence.

## v0.6 — authority-safe APS interoperability

Agent Replay now accepts APS oracle-safety-check evidence without collapsing claims, authority, policy, and execution into one status.

```bash
agent-replay reconstruct fixture.json --format aps
agent-replay reconstruct fixture.json --format aps --json -o aps-incident.json
agent-replay export-share aps-incident.json -o aps-public-share.json
```

The APS reconstruction separates:

- adapter validation provenance from the provenance of the supplied input,
- external APS conformance from Replay's own structural checks,
- claimed signer identity from independent cryptographic verification,
- action, receipt, delegation-chain, and policy binding,
- pre-dispatch permit decisions from post-dispatch execution evidence.

Execution evidence is graded as `NO_EXECUTION_EVIDENCE`, `EXECUTION_EVIDENCE_UNBOUND`, `EXECUTION_EVIDENCE_PARTIALLY_BOUND`, or `EXECUTION_EVIDENCE_BOUND_TO_ACTION`. Agent Replay does not currently claim independent Ed25519/EIP-712 verification.

The optional DDC adapter can map APS reconstruction into an evidence graph with explicit delegation → intent → policy → execution boundaries. Radial findings remain non-authoritative candidate hypotheses.

The release regression suite vendors the exact 13 APS fixtures from `Agent-Authority-Conformance/aps-conformance-suite@6e8b05b202d727ef18e84e100fc31db11f36529f`.

## v0.5 — hardened replay and safer evidence handling

v0.5 keeps the standalone, zero-runtime-dependency core while tightening the places where forensic tools most often become ambiguous or unsafe.

### Easier first use

Input format is now auto-detected from normal file extensions:

```bash
agent-replay reconstruct examples/refund-750/events.jsonl
agent-replay reconstruct examples/refund-750/otel.json
```

`--format jsonl` and `--format otel` remain available when an explicit override is preferable.

Useful operator commands:

```bash
agent-replay --version
agent-replay doctor
agent-replay reconstruct evidence.jsonl --json -o incident.json
```

Normal errors are concise. Use `--debug` when a traceback is needed.

### Bounded evidence processing

Untrusted or accidentally huge evidence is bounded by default:

```text
max bytes    32 MiB
max events   100,000
max parents  64 per event
max depth    4,096
```

The reconstruction command exposes `--max-bytes`, `--max-events`, `--max-parents`, and `--max-depth` when a reviewed workload requires different limits.

### Direct OTLP reconstruction

OTLP input is normalized directly into canonical events and reconstructed in memory. Agent Replay no longer writes a temporary canonical JSONL file and then re-opens it merely to reconstruct an OTLP incident.

Explicit JSONL export remains available when a canonical artifact is actually wanted:

```bash
agent-replay ingest otel examples/refund-750/otel.json -o canonical.jsonl
```

### Reproducibility check

A prior machine-readable incident can be replayed against its evidence:

```bash
agent-replay reproduce incident.json examples/refund-750/events.jsonl
```

The comparison checks the normalized evidence hash, event count, reconstruction status, first provable divergence, causal-chain signature, and the incident's supplementary evidence scope.

When the original incident includes verified TRACE evidence, replay the same independently supplied TRACE record and trusted key:

```bash
agent-replay reproduce \
  incident.json \
  examples/refund-750/events.jsonl \
  --trace-record session.trace.json \
  --trace-key issuer-public.pem
```

TRACE-aware reproduction re-verifies and compares the TRACE record SHA-256, trusted-key SHA-256, and supplementary evidence-bundle binding. Results are:

```text
REPRODUCED   same core reconstruction and same evidence scope
INCOMPLETE   core reproduced but required supplementary TRACE evidence was not replayed
DRIFTED      core or supplied supplementary evidence differs
```

Agent Replay therefore does not report plain `REPRODUCED` for a TRACE-backed incident unless that supplementary evidence was actually replayed.

Ordinary reconstruction still reports `reproducibility = NOT_TESTED` until this check is actually run.

### Safer external sharing

Public share exports redact assertion values by default:

```bash
agent-replay export-share incident.json -o public-share.json
```

The recipient can still see that an assertion changed and the expected/observed value types without receiving the values themselves. Scalar values require explicit opt-in:

```bash
agent-replay export-share incident.json --include-values -o reviewed-share.json
```

Even opted-in exports still pass the fail-closed sensitive-data scan. See [docs/SECURE_SHARING.md](docs/SECURE_SHARING.md).

### DDC Radial provenance

The optional DDC adapter now distinguishes mapping provenance instead of making defaults look equivalent to evidence:

```text
EXPLICIT   supplied by evidence
INFERRED   derived from bounded event-kind heuristics
DEFAULT    adapter fallback
```

Radial remains non-authoritative. Its candidate findings do not alter Agent Replay's reconstruction.

## v0.4 — AgenTrust TRACE evidence

Agent Replay can verify a standalone TRACE v0.2 Trust Record against a caller-supplied trusted issuer key and attach the verified record summary to an incident reconstruction.

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

The current adapter verifies the standalone TRACE record's schema/profile, cryptographic signature, and freshness through the audited `agentrust-trace` **0.9.0** verifier (`==0.9.0`). It does **not** independently verify:

- hardware attestation evidence,
- transparency-ledger inclusion,
- cMCP RuntimeClaim envelopes,
- or that the incident input is the external transcript committed by `tool_transcript.hash`.

Those distinctions are preserved in the emitted verification scope rather than inferred.

## OpenTelemetry ingestion

Agent Replay can reconstruct directly from OpenTelemetry OTLP JSON.

```bash
python -m pip install -e .
agent-replay reconstruct examples/refund-750/otel.json
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
agent-replay reconstruct examples/refund-750/otel.json --json
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

Agent Replay fails closed on invalid or timezone-less timestamps, duplicate event IDs, unknown or duplicate parents, self-parenting, future-parent edges, causal cycles, excessive parent fan-in, excessive causal depth, excessive event count, and evidence exceeding the configured byte limit.

Timestamps are normalized to UTC before ordering. Equal-time events are topologically ordered so an evidenced parent cannot be placed after its child. Events without expected-state evidence are labeled `UNASSESSED`, not `VALID`.

Each reconstruction contains:

```text
input_sha256
canonical_sha256
```

The first hashes the exact evidence bytes supplied by the caller, including the original OTLP JSON. The second hashes the normalized canonical representation. When verified TRACE evidence is attached, the TRACE record and trusted key are individually hashed and a supplementary evidence-bundle hash binds those fingerprints to the incident.

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
agent-replay-ddc review examples/refund-750/otel.json --format otel
```

Machine-readable Radial output now also reports aggregate mapping provenance so downstream reviewers can see how much of the graph came from explicit evidence versus inference/defaults.

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
agent-replay reconstruct examples/refund-750/otel.json --json \
  | agent-replay-ddc-radial
```

Use `--json` on the Radial command for full feature vectors:

```bash
... | agent-replay-ddc-radial --json
```

DDC Radial findings remain non-authoritative candidate hypotheses. They are structural fault hypotheses and falsification proposals, not Agent Replay findings, blame assignments, or execution authority.

Deleting `adapters/ddc/` leaves Agent Replay fully functional.

## Machine-readable contracts

```text
schemas/incident-v2.schema.json
schemas/aps-authority-reconstruction-v2.schema.json
schemas/public-share-v1.schema.json
schemas/public-aps-share-v1.schema.json
schemas/public-radial-review-v1.schema.json
schemas/share-bundle-v1.schema.json
```

The internal incident and externally shareable artifacts have separate schemas intentionally; sanitization is a representation boundary, not a presentation flag.

## Development and release assurance

Install development/schema dependencies and run the bounded release suite:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

The root pytest configuration collects both the standalone core tests and `adapters/ddc/tests`, so DDC adapter unit contracts are part of the normal release gate. The real TRACE verifier lane remains separate because it requires the optional pinned dependency `agentrust-trace==0.9.0`.

Normal runtime use still requires no third-party core dependencies:

```bash
python -m pip install -e .
```

Optional DDC adapter:

```bash
python -m pip install -e ./adapters/ddc
```

Before a release, also verify the built core wheel in a fresh virtual environment:

```bash
python tools/release_smoke.py
```

That smoke gate builds the wheel through the declared build backend, extracts the wheel into an isolated temporary import target, verifies the packaged console entry point/import path, and exercises `agent-replay --version`, `doctor`, reconstruction, and safe-share export. Install `.[dev]` first so the test environment contains the declared build backend used by the smoke gate.

Benchmark reconstruction on deterministic synthetic chains:

```bash
python benchmarks/benchmark_reconstruct.py --events 1000 10000 100000
```

The DDC checkout referenced by `DDC_RADIAL_ROOT` is executable local code and must be treated as trusted.

No hosted infrastructure or GitHub Actions are required.

## Author

Created by **Valentyn Rukhaylo / Altru.dev**

LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

## License

Apache-2.0
