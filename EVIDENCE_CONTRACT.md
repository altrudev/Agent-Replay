# Agent Replay Evidence Contract — Baseline 1.0

This document freezes the governing evidentiary principles for Agent Replay. It is the architectural baseline against which future code, adapters, marketplace integrations, renderers, and exports must be reviewed.

Agent Replay exists to answer a narrow question:

> What was asked, what evidence exists, what was authorized, what happened, and where can the supplied evidence prove that those things diverged?

The contract is intentionally stricter than a generic observability or AI-summary system. Agent Replay must never produce a stronger claim than its evidence supports.

## 1. Core product boundary

Agent Replay is a platform-independent evidence reconstruction engine. It is not an agent runtime, policy engine, monitoring platform, blame engine, or centralized evidence warehouse.

The standalone core MUST remain usable without OpenAI, Anthropic, Google, Microsoft, DDC, TRACE, or any hosted Altru service.

Local and customer-hosted operation are first-class deployment modes. Marketplace integrations are distribution/adaptation layers, not the source of truth for Agent Replay semantics.

## 2. Evidence stays inside the existing trust boundary by default

Agent Replay should go to the evidence whenever the deployment model permits it.

Local mode: evidence remains local.

Customer-hosted mode: evidence remains inside the customer-controlled environment.

Platform-native mode: evidence remains inside the host platform when the platform provides a supported execution path that does not require transmission elsewhere.

If a marketplace or protocol requires remote processing, that boundary MUST be explicit. Agent Replay MUST NOT claim that evidence remains local when the transport contradicts that claim.

No deployment mode may silently change its evidence-processing boundary.

## 3. No central evidence service requirement

Agent Replay MUST NOT require a central Altru evidence database, replay-history warehouse, or permanent incident ingestion pipeline.

Any compatibility-mode remote processor MUST be designed for minimum necessary evidence, bounded execution, body-log suppression, and no application-level retention. Operational infrastructure claims such as zero retention MUST be verified across the full request path before being advertised.

Licensing, update checks, schemas, release metadata, and billing MUST be separable from replay evidence.

## 4. Deterministic findings, optional presentation

The forensic result MUST be produced by deterministic rules over supplied evidence.

A language model MAY assist presentation, search, or optional explanation, but it MUST NOT determine the underlying forensic finding.

The authoritative layer consists of canonical evidence, comparisons, relationships, claim status, evidence references, and integrity values.

Natural-language explanation is a rendering of those findings and MUST NOT strengthen them.

## 5. Absence of evidence is not evidence of absence

A missing observation MUST NOT automatically become a mismatch.

Agent Replay MUST distinguish at least:

- MATCH
- MISMATCH
- NOT_OBSERVED
- NOT_COMPARABLE

JSON null, an absent field, and an explicit false/none value are distinct states unless a schema explicitly defines otherwise.

A negative conclusion such as “no approval occurred” requires evidence that establishes the relevant evidence channel as complete for the relevant scope. Otherwise the correct claim is limited to wording such as “no approval was found in the supplied evidence.”

## 6. Coverage is evidence

Evidence completeness and coverage claims MUST themselves have provenance.

Examples include conversation coverage, tool-call coverage, approval-channel coverage, time-window coverage, and export completeness.

Agent Replay MUST distinguish between authenticated completeness, asserted completeness, partial coverage, and unknown coverage where the source format supports those distinctions.

Caller-supplied “complete” assertions MUST NOT silently become authenticated completeness.

## 7. Human intent is not mind-reading

Agent Replay MUST distinguish expressed instructions from inferred intent.

The preferred human-facing label is “You asked” when the source is an explicit instruction.

Agent Replay MUST NOT say “the agent understood” unless interpretation/plan evidence explicitly supports that statement.

When such evidence is absent, acceptable language includes “the next evidenced action was” or “the action was inconsistent with the supplied request.”

## 8. Authority is independent of request and action

Request, authority, approval, delegation, revocation, execution, and outcome are independent evidence dimensions.

Approval existence MUST NOT be represented as a simple timeless boolean when the evidence provides temporal or scoped authority.

Where available, authority may bind:

- operation
- subject
- target/resource
- amount or other quantitative limit
- account or credential
- time window
- delegation scope
- preconditions

Revocation and expiry MUST be capable of invalidating earlier approval for later execution.

Agent-to-agent delegation MUST NOT be silently upgraded to human authorization.

## 9. Constraints are explicit, not guessed

Agent Replay MAY support deterministic constraint operators such as:

- equals
- maximum
- minimum
- one-of
- prohibited / must-not
- requires-approval
- valid-until

Constraint semantics MUST be versioned and deterministic. Unsupported critical operators MUST fail closed rather than being silently ignored.

## 10. Chronology does not automatically imply causality

Temporal sequence and causal relationship are distinct.

A later event MUST NOT be called causal merely because it happened later.

Unrelated equal-time events may be serialized deterministically for stable output, but deterministic tie-breaking MUST NOT be presented as evidentiary proof of order.

Agent Replay MUST be capable of representing concurrent or order-not-established relationships.

If multiple divergences are equally early and their ordering is not established, Agent Replay MUST NOT invent a single first divergence.

## 11. Identity claims remain claims unless authenticated

Actor names and labels are evidence labels unless independently authenticated.

Agent Replay MUST NOT convert `actor = "X"` into a claim that the real-world entity X performed the action without authentication evidence.

Where available, identity continuity may bind actor instance, runtime instance, agent version, session, credential, tool identity, server identity, or other authenticated identifiers.

## 12. Tool and policy continuity matter

Forensic interpretation may depend on the exact tool, schema, server, policy, or runtime version in effect when an action occurred.

Where available, events should bind version/digest information such as:

- tool identity
- tool schema digest
- tool version
- server identity
- policy ID/version/digest
- effective time
- runtime identity/version

Agent Replay MUST NOT silently assume that a repeated label identifies an unchanged capability or policy.

## 13. Claim strength is explicit

Findings SHOULD distinguish claim basis such as:

- DIRECT_EVIDENCE
- DETERMINISTIC_DERIVATION
- ASSERTED
- NOT_ESTABLISHED

Human-facing output MUST avoid blame-like wording when the engine only has event association.

Terms such as “responsible,” “at fault,” “owned the failure,” or equivalent MUST NOT be inferred from ordinary actor labels or temporal position.

## 14. Confidence must not hide evidence limitations

A naked HIGH/MEDIUM/LOW label MUST NOT be used as a substitute for evidence quality.

Human-facing output should expose relevant dimensions explicitly, for example:

- structural support
- evidence coverage
- source authentication
- actor authentication
- causal support

Any retained internal structural-confidence signal MUST be clearly scoped and MUST NOT imply independent truth.

## 15. Integrity and reproducibility

Agent Replay MUST preserve an integrity binding to the exact supplied evidence and a separate binding to the canonical representation.

Canonicalization used for cross-implementation digests MUST eventually be specified in a language-independent way so conforming Python, Rust/WASM, JavaScript, Java, or other implementations can produce identical canonical digests.

Source-line numbers and formatting positions are provenance metadata, not stable record identity.

Replay output SHOULD identify the engine version, schema/ruleset version, and build or artifact digest where practical.

## 16. Export is a separate authority transition

Analyzing evidence does not authorize sharing it.

Normal replay MAY remain ephemeral. Persistent export MUST be an explicit user action.

Before export, the implementation SHOULD make clear what data will leave the current trust boundary and SHOULD support local redaction where practical.

An export MUST distinguish findings reproducible from the exported bundle from findings that depended on redacted or omitted evidence.

Portable bundles SHOULD include a claims manifest linking claims to evidence references and indicating reproducibility from the bundle.

## 17. Evidence is data, never control

Content inside replay evidence MUST be treated as inert data.

Prompts, tool outputs, documents, or other evidence containing instructions MUST NOT be permitted to alter Agent Replay configuration, retention, network access, tool use, export scope, or authorization.

The standalone forensic core SHOULD require no network, shell, or arbitrary tool execution for ordinary reconstruction.

## 18. Bounded hostile-input handling

Untrusted evidence MUST NOT be allowed to consume unbounded resources.

Implementations SHOULD enforce limits as early as possible on dimensions including:

- total input bytes
- individual record bytes
- event count
- parent/edge count
- string sizes
- nesting depth
- graph depth/width where applicable
- report/output size
- processing time and memory in remote/public deployments

A limit failure MUST fail clearly and must not produce a partial forensic verdict that looks complete.

## 19. Schema evolution fails safely

Unknown non-critical extensions may be preserved and marked unsupported.

Unknown critical fields, operators, or semantics that can affect a forensic result MUST fail closed.

Adapters MUST NOT silently discard critical evidence needed to reproduce a finding.

## 20. Platform adapters are translation boundaries

Adapters may parse, normalize, map, preserve source metadata, and validate representation.

Adapters MUST NOT independently assign blame, invent human intent, strengthen evidence, or bypass core forensic semantics.

The same canonical evidence should produce the same authoritative Agent Replay finding regardless of whether it arrived through CLI, OpenTelemetry, MCP, A2A, a marketplace adapter, or another supported transport.

## 21. DDC Radial remains advisory

DDC Radial is an optional investigation layer.

Agent Replay answers: what can the supplied evidence prove?

DDC Radial may answer: what else should be investigated or falsified?

Radial findings MUST remain non-authoritative candidates unless separately established by Agent Replay evidence.

## 22. Prohibited claim patterns

Regression tests SHOULD ensure the renderer does not say:

- “You approved …” when approval is inferred or merely absent elsewhere.
- “The agent understood …” without explicit interpretation evidence.
- “The agent caused …” without causal evidence.
- “You never …” without authenticated complete coverage for the relevant scope.
- “The agent was responsible / at fault …” from actor labels or ordering alone.
- “This definitely happened …” when source authenticity is not established.

## 23. Governing rule

Every new feature, integration, renderer, constraint operator, and export format is evaluated against this question:

> Does this change make Agent Replay claim more than the evidence can support?

If yes, the change MUST be rejected or redesigned unless stronger evidence is explicitly required and validated.

This baseline is the design constitution for the next Agent Replay development line. Implementation details may evolve; these evidentiary principles do not change casually.

## Authenticated execution-boundary evidence

Agent Replay may optionally verify three distinct execution-boundary claims:

1. **Expected-state provenance** — a caller-trusted Ed25519 signer binds an expected state to a policy identity, authority version, event, action, scope, and validity interval.
2. **Revocation delivery** — a caller-trusted execution-boundary signer acknowledges a specific, hash-bound revocation event before execution.
3. **Execution-time evaluation** — a caller-trusted boundary signer proves that it evaluated the delivered authority state before the execution event and binds that evaluation to the event's observed decision state.

These stages are intentionally independent. A valid delivery receipt MUST NOT be interpreted as proof that the boundary evaluated the received state. A valid evaluation MUST NOT become an enforcement claim unless the expected policy is independently authenticated and the evaluation is bound to the verified delivery evidence.

Agent Replay reports enforcement consistency only when policy provenance, delivery, and execution-time evaluation are all verified. Otherwise it preserves the unresolved boundary explicitly.

Cryptographic validity is not organizational authority. Trust in a signer is supplied by the caller; Agent Replay does not infer legal authority, organizational entitlement, or real-world identity continuity from possession of a valid signing key.
