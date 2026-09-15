# Changelog

All notable changes to Agent Replay are documented here.

## 0.4.2

Compatibility-only update for the audited TRACE v0.9.1 verifier line.

### Changed

- Optional TRACE dependency updated to `agentrust-trace>=0.9.1,<0.10.0`.
- Agent Replay TRACE integration continues to use the stable `validate_json()` + `verify_record()` path with a caller-supplied trusted key.
- Core reconstruction, causality, attribution, OTLP handling, incident schema, and DDC Radial behavior are unchanged from v0.4.1.
- Core and optional DDC adapter package versions aligned at 0.4.2.

## 0.4.1

Release-hardening pass following the full repository DDC Radial audit.

### Correctness and provenance

- Events without expected-state evidence are reported as `UNASSESSED`, not `VALID`.
- Reconstruction no longer claims execution reproducibility; `reproducibility` is `NOT_TESTED`.
- Equal-time causal events are topologically ordered so a parent cannot appear after its child.
- OTLP ordering preserves exact `startTimeUnixNano` values.
- OTLP `input_sha256` binds the original caller-supplied OTLP document.
- OTLP documents containing multiple traces fail closed unless a trace is explicitly selected.
- `parentSpanId` remains ancestry/provenance unless `agent.replay.causal_parent=true` is explicitly supplied.
- Expected-state and confidence trust boundaries are emitted in the incident document.
- TRACE evidence includes hashes for both the exact record and the caller-supplied trusted key.
- Supplementary TRACE evidence is bound to the incident with a combined evidence-bundle hash.
- DDC Radial output records the exact engine source SHA-256.
- The DDC adapter hashes and executes the same source bytes, closing the engine load TOCTOU gap.
- Radial representation, authority, relation, independence, atomicity, consequence, freshness, and recovery features are not inferred from actor/event names when evidence is absent.

### Packaging and hardening

- Core and DDC adapter versions aligned.
- Optional TRACE dependency constrained to the compatible 0.5.x verifier line.
- Full Apache License 2.0 text included.
- Security and sensitive-evidence handling policy added.
- JSON Schema validation added to the development test suite.

## 0.4.0

- Optional AgenTrust TRACE evidence verification and attachment.
- Caller-supplied TRACE issuer trust root.
- DDC Radial provenance and falsification-oriented candidate review.

## 0.3.0

- OpenTelemetry OTLP JSON ingestion.
- Canonical JSONL normalization.
- Evidence sufficiency reporting.

## 0.2.0

- Canonical event model.
- Divergence reconstruction.
- Explicit causal versus temporal downstream distinction.
- Evidence attribution labels and machine-readable incident schema.

## 0.1.0

- Initial standalone Agent Replay prototype.
