# Security Policy

## Supported release

The current supported development line is Agent Replay 0.4.x.

## Reporting a vulnerability

Please report security issues privately to the repository owner before public disclosure. Include:

- affected version or commit,
- reproduction steps,
- expected versus observed behavior,
- whether the issue concerns evidence integrity, parsing, provenance, trust boundaries, or the optional DDC/TRACE integrations.

Do not include real credentials, secrets, production customer data, or private incident evidence in a public issue.

## Evidence handling

Agent Replay is a local CLI and does not require a hosted service for core reconstruction. Evidence files may still contain sensitive information.

Before sharing an incident bundle, review and redact:

- API keys and bearer tokens,
- cookies and session identifiers,
- customer identifiers,
- payment data,
- prompts containing confidential data,
- tool inputs/outputs containing secrets,
- internal URLs, hostnames, file paths, and infrastructure metadata.

Agent Replay currently does not automatically redact sensitive values from `expected`, `observed`, evidence metadata, TRACE summaries, or reports.

## Trust boundaries

Agent Replay intentionally distinguishes evidence from proof:

- `expected` values are caller-supplied assertions unless independently bound to policy evidence.
- Actor labels are evidence labels, not independently authenticated identities.
- OpenTelemetry `parentSpanId` is ancestry, not causality, unless `agent.replay.causal_parent=true` is explicitly supplied.
- DDC Radial findings are non-authoritative candidate hypotheses.
- `agent.replay.radial.*` / `evidence.radial` structural hints may be caller supplied and are not independently authenticated.
- TRACE verification depends on the caller-supplied trusted key and the supported `agentrust-trace` verifier.
- `DDC_RADIAL_ROOT` points to executable local Python source. Treat that checkout as trusted code.

The governing evidentiary principles are frozen separately in [EVIDENCE_CONTRACT.md](EVIDENCE_CONTRACT.md). Where implementation behavior and the Evidence Contract differ, that difference is a defect or an explicitly documented compatibility limitation; it must not be silently normalized into a stronger claim.

## Resource limits

Agent Replay does not yet impose configurable hard limits on evidence file size, event count, graph width, or report size. Do not process untrusted, arbitrarily large inputs in a privileged environment.

For hostile or untrusted evidence, run Agent Replay in an OS-level sandbox/container with bounded memory, CPU, file access, and execution time.

Resource bounding is a required hardening item before exposing Agent Replay as a public remote processor.

## Optional DDC integration

The standalone Agent Replay core does not require DDC.

The optional DDC adapter loads the local file:

```text
$DDC_RADIAL_ROOT/src/radial_frequency_v10.py
```

The adapter hashes and executes the same byte buffer and records its SHA-256 in the result. This protects engine provenance, but it does not make an untrusted DDC checkout safe to execute.

## Dependency policy

Core Agent Replay has no runtime third-party dependencies.

Optional TRACE support is pinned to `agentrust-trace==0.9.0` by the current package metadata. Security documentation and release notes must be updated together if that supported verifier version changes.

Development/schema validation dependencies are optional and are not required for normal reconstruction.
