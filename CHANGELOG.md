# Changelog

All notable changes to Agent Replay are documented here.

## 0.5.1

Assurance-closure patch following the v0.5.0 post-release sweep.

### Fixed

- `agent-replay reproduce` no longer reports plain `REPRODUCED` when the original incident contains TRACE evidence that was not replayed.
- TRACE-aware reproduction now compares the TRACE record SHA-256, caller-supplied trusted-key SHA-256, and supplementary evidence-bundle binding.
- Missing supplementary TRACE evidence reports `INCOMPLETE`; mismatched supplementary evidence reports `DRIFTED`.
- Core and DDC adapter module `__version__` values are aligned with package metadata.

### Assurance

- Root release tests now collect both standalone core tests and `adapters/ddc/tests` so the optional adapter unit contracts are included in the bounded pytest release gate.
- Added release-metadata consistency tests to prevent module/package/adapter version drift.
- Added a clean-wheel release smoke harness that builds and installs the core wheel into a fresh virtual environment, then exercises `--version`, `doctor`, reconstruction, and safe-share export.
- Added package discovery metadata and canonical project URLs.
- TRACE verifier coverage remains a separate optional-dependency lane pinned to `agentrust-trace==0.9.0`.

Evidence Contract 1.0 input semantics remain unchanged.

## 0.5.0

Security, determinism, usability, and scale hardening without changing the Evidence Contract 1.0 input model.

### Added

- `agent-replay reproduce` for deterministic replay comparison.
- `agent-replay doctor` for core/TRACE/DDC readiness checks.
- Input resource limits for bytes, events, parent fan-in, and causal depth.
- Public JSON Schemas for sanitized incidents, sanitized Radial reviews, and share bundles.
- Deterministic benchmark harness for 1k/10k/100k-event reconstruction measurements.
- Explicit provenance accounting for DDC Radial mappings (`EXPLICIT`, `INFERRED`, `DEFAULT`).

### Changed

- OTLP reconstruction now normalizes directly in memory instead of writing and re-reading a temporary JSONL file.
- Divergent ancestry is computed once in topological order instead of traversing the graph independently for every divergence.
- CLI input format defaults to auto-detection and supports output files, controlled error messages, `--debug`, and `--version`.
- Incident schema now formally covers evidence gaps, evidence completeness, scoped TRACE evidence, and reproducibility states.
- Public share bundles redact assertion values by default; scalar values require explicit `--include-values` opt-in and still pass the fail-closed sensitive-data scan.
- DDC Radial defaults and naming-based dimension heuristics are exposed as provenance rather than silently appearing equivalent to supplied evidence.
- Isolated test runners explicitly add the repository `src/` layout, improving reproducibility under bounded DSR execution.

## 0.4.3

Reproducibility repair for the TRACE marketplace integration.

### Changed

- Pin the optional TRACE verifier to the actually published `agentrust-trace==0.9.0` release.
- Replace the unreleased 0.9.1 compatibility claim; PyPI publishes 0.9.0 and then 0.10.0.
- Add real-verifier integration coverage for a valid signed record, tampering, and a wrong caller-supplied trusted key.
- Core reconstruction behavior is unchanged.

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
