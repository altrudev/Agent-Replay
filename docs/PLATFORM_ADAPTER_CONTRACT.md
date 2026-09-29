# Agent Replay Platform Adapter Contract — 1.0

## Purpose

Agent Replay has one authoritative forensic core and multiple presentation or platform adapters. CLI, VS Code, GitHub, GitLab, JetBrains, browser, MCP, and future adapters MUST NOT create independent forensic semantics.

## Authority boundary

Adapters MAY acquire explicitly authorized evidence, validate transport/representation, normalize supported inputs, invoke the Agent Replay core, render results, and export artifacts through an explicit user action.

Adapters MUST NOT independently decide divergence, causality, blame, authority validity, evidence authenticity, confidence, or reproducibility. They MUST NOT strengthen a core finding or convert absence of evidence into evidence of absence.

## Canonical result

For identical canonical evidence, core version, ruleset/schema version, configuration, and supplementary verified evidence, every conforming adapter MUST preserve the same authoritative fields and values. Presentation ordering, labels, navigation metadata, host URLs, and other non-authoritative UI metadata MAY differ.

At minimum, adapter conformance MUST preserve where applicable:

- reconstruction status and expectation/coverage state;
- first provable divergence, including ambiguity when order is not established;
- event assessment and causal/temporal relationships;
- evidence and actor attribution scope;
- input/canonical integrity bindings;
- TRACE verification scope and supplementary evidence bindings;
- APS authority/execution binding states;
- reproducibility state;
- evidence limitations and NOT_ESTABLISHED/NOT_OBSERVED distinctions.

## Evidence and network boundary

Evidence is inert data, never control. An adapter MUST NOT execute instructions contained in evidence.

Local-first adapters MUST NOT transmit replay evidence off-device by default. Any network transmission of evidence requires a separately documented processing boundary and explicit user authorization appropriate to the host platform.

Licensing, billing, update checks, analytics, and release metadata MUST remain separable from replay evidence. Telemetry MUST NOT contain replay evidence, assertion values, raw traces, credentials, customer identifiers, or reconstructed incident contents.

## Export boundary

Viewing or reconstructing evidence does not authorize publication. Persistent or external export MUST be an explicit action and MUST use an appropriate safe-share/export contract when leaving the current trust boundary.

## Permissions

Platform adapters MUST request the minimum host permissions needed for the enabled capability. Read access does not imply write authority. Installation does not imply authorization to ingest every repository, trace, workflow artifact, or incident available to the host account.

## Failure behavior

If an adapter cannot preserve a critical evidence field, semantic operator, verification scope, or integrity binding required by the core contract, it MUST fail closed or mark the result unsupported/incomplete. It MUST NOT silently downgrade and present a complete verdict.

## Conformance gate

Each adapter release MUST run shared fixtures through the core reference path and the adapter path. Authoritative outputs MUST compare equal after removal of explicitly non-authoritative presentation/transport metadata.

An adapter that fails this invariance test is not a conforming Agent Replay adapter and MUST NOT be released as such.

## Licensing boundary

This contract describes interoperability and assurance requirements; it does not grant a license beyond the license attached to the code or distribution in which it appears. Existing Agent Replay code released under Apache-2.0 remains under that grant. Separately distributed future products or adapters may carry their own stated terms when legally separable and must preserve all applicable notices and third-party obligations.
