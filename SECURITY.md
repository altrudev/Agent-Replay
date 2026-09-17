# Security Policy

## Supported release

The current supported development line is Agent Replay 0.5.x.

## Reporting a vulnerability

Please report security issues privately to the repository owner before public disclosure. Include:

- affected version or commit,
- reproduction steps,
- expected versus observed behavior,
- whether the issue concerns evidence integrity, parsing, provenance, trust boundaries, resource bounding, or the optional DDC/TRACE integrations.

Do not include real credentials, secrets, production customer data, or private incident evidence in a public issue.

## Evidence handling

Agent Replay is a local CLI and does not require a hosted service for core reconstruction. Evidence files may still contain sensitive information.

Raw incident JSON is an internal evidence artifact and can contain expected/observed values, evidence metadata, actor labels, timestamps, TRACE summaries, file paths, customer identifiers, or other confidential material. Do not treat it as safe to publish.

For external sharing, use the allowlist-only export path documented in [docs/SECURE_SHARING.md](docs/SECURE_SHARING.md). Public exports pseudonymize semantic identifiers, omit raw evidence and timestamps, and redact assertion values by default. `--include-values` is an explicit disclosure opt-in, not the default.

The final public bundle is scanned for common bearer tokens, credential-shaped values, `/home/...` paths, IP addresses, and email addresses. This scan is defense in depth, not proof that an opted-in value is non-confidential.

## Trust boundaries

Agent Replay intentionally distinguishes evidence from proof:

- `expected` values are caller-supplied assertions unless independently bound to policy evidence.
- Actor labels are evidence labels, not independently authenticated identities.
- OpenTelemetry `parentSpanId` is ancestry, not causality, unless `agent.replay.causal_parent=true` is explicitly supplied.
- DDC Radial findings are non-authoritative candidate hypotheses.
- DDC Radial mappings distinguish `EXPLICIT`, `INFERRED`, and `DEFAULT` provenance; inferred/defaulted mappings must not be presented as supplied evidence.
- `agent.replay.radial.*` / `evidence.radial` structural hints may be caller supplied and are not independently authenticated.
- TRACE verification depends on the caller-supplied trusted key and the supported `agentrust-trace` verifier.
- `DDC_RADIAL_ROOT` points to executable local Python source. Treat that checkout as trusted code.

The governing evidentiary principles are frozen separately in [EVIDENCE_CONTRACT.md](EVIDENCE_CONTRACT.md). Where implementation behavior and the Evidence Contract differ, that difference is a defect or an explicitly documented compatibility limitation; it must not be silently normalized into a stronger claim.

## Resource limits

Agent Replay 0.5 applies fail-closed default limits to untrusted evidence:

```text
max input bytes   32 MiB
max events        100,000
max parents       64 per event
max causal depth  4,096
```

The reconstruction CLI exposes explicit limit overrides for reviewed workloads. Raising a limit increases the caller's resource-exhaustion exposure and should be treated as an operational decision rather than an input request.

These limits bound important attack surfaces but do not replace OS-level isolation. For hostile evidence, use an OS-level sandbox/container with bounded memory, CPU, filesystem access, and execution time.

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
