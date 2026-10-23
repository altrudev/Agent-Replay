# Evidence-state v1: bounded offline forensic assessment

This is a separate contract, `agent-replay.evidence-state.v1`, with distinct
input/output JSON schemas. It does not reinterpret incident-v2 or replace the
existing reconstruction engine. Core requires only Python 3.10+ standard library.
No model, DDC, TRACE, service, network, or proprietary source is involved.

```
PYTHONPATH=src python3 -m agent_replay.cli assess-evidence input.json
PYTHONPATH=src python3 -m agent_replay.cli assess-evidence input.json --trust-anchors operator-keys.json
```

The CLI writes bounded JSON to stdout. Persisting it requires explicit shell
redirection. There is no automatic export, evidence store, or public share adapter
for this schema. Existing share formats apply to their existing schemas only.
Reports contain hashed references, clocks, fixed enum findings and provenance
digests, never original identifiers, arbitrary content, signatures, or key bytes.
Timestamps and linkable digests can still be sensitive: this is a local forensic
result, not a certified public disclosure artifact. Release metadata is separate.

The authoritative field manifest includes every new output field. API
`assess(document, trust_anchors=...)` computes canonical integrity;
`assess_bytes(raw, trust_anchors=...)` also binds exact input bytes. CLI uses the
latter. JSON duplicate keys, floating point, nonfinite numbers, unknown fields,
unsupported event kinds and ambiguous occurrence aliases fail closed. Invalid
input yields an error, never a partial verdict. Input and output schemas live in
`schemas/evidence-state-v1.{input,output}.schema.json`; runtime additionally
validates clocks, references, total budgets and trust semantics.

## Clocks and knowledge

A decision names an actor instance, time, interval start, action, subject,
credential, channel and source. Events carry an evidence ID, source, actor,
subject/action/channel, kind, authority scope and three clocks: `event_at` (or
exactly one alias `occurred_at`), `observed_at`, `ingested_at`. Event time is
occurrence/effective time, not an ingestion surrogate. Approval scope requires
credential, operation, resource and valid-until. All timestamps are integer epoch
nanoseconds or aware RFC3339 with up to nine fractional digits. Parsing uses
integer arithmetic; floats, naive dates, leap seconds, unknown `-00:00` offsets
and invalid calendars fail closed. Event <= observation <= ingestion is required.

Receipts bind the SHA-256 of the event signable payload (`evidence_sha256`),
its evidence ID and recipient actor instance, a source,
`delivered` or `consulted`, receipt time, observation time and ingestion time.
Occurrence <= receipt <= receipt observation <= receipt ingestion is required.
Receipt need not await central event ingestion. All receipt provenance is retained
as digests. Knowledge depends on the decision actor, not the event's actor label.

* LATER_OBSERVED: event occurrence or observation is after the decision.
* KNOWN: a source-authenticated delivered/consulted receipt and its observation
  are at or before decision time. This can be knowledge of a reported assertion;
  event authenticity remains a separate dimension.
* MAYBE_AVAILABLE: such timely receipt exists but its source is not authenticated.
* NOT_ESTABLISHED: no timely receipt for that actor, including late receipt.

Late ingestion alone does not erase authenticated earlier delivery. Future
observations cannot be used as earlier knowledge. Authentication proves an
operator-trusted source attested a record, not real-world actor identity,
comprehension, intent or causality. There is no chronology-derived causal edge.
Equal-time events serialize by evidence ID solely for determinism. Contradictory
records remain separate with their provenance and authority diagnostics.

## Trust and coverage

Separately supplied API anchors map key ID to `{source: str, key: bytes}` with at
least 32 key bytes. The CLI reads an operator-owned separate JSON mapping from
key ID to `{source, key_hex}`; no embedded keys are accepted. Operators must use
random keys, protect their file, and authenticate source enrollment out of band.
The library does not retrieve secrets or establish that enrollment itself.

HMAC-SHA256 signs ASCII JSON of `{schema, context_id, kind, record}`, with keys
sorted, compact separators, ensure_ascii enabled, integers decimal, and the
record's `signature` member omitted. `kind` is `event`, `receipt`, or `coverage`.
This deliberately limited v1 canonical profile allows no floating point or
Unicode normalization. Producers can use `signable` and `signature` helpers.
`key_id`, all scope and temporal fields and context are signed. Verification
uses `hmac.compare_digest`. A key is accepted only for its operator-bound source.
Changing context, kind, actor, source, interval, contents or scope invalidates the
signature. Context IDs must be unique in the operator's case namespace; the
caller must choose the intended context, not accept an attacker's replacement
case as the same case. HMAC is shared-secret source authentication, not public
nonrepudiation or proof of source honesty. Signers can lie or omit events.

A supplied signature without a matching external anchor stays
SUPPLIED_ASSERTION. This implementation deliberately has no untrusted-key
verification mode and never claims SIGNATURE_VALID_UNTRUSTED or independent
verification from self-attestation. Fields such as `verified=true` are rejected.
The result includes a digest binding operator source/key configuration for
reproducibility without emitting keys or individual key fingerprints.

Coverage requires manifest ID, source, actor/channel/action/subject, exact start
and end, observed/ingested times, completeness boolean and exhaustive evidence-ID
list for that scope and interval. End <= observation <= ingestion is mandatory.
Only a valid source-bound signature yields AUTHENTICATED_COVERAGE. A negative
approval finding additionally requires complete=true, exact decision scope and
interval, and a manifest list matching all supplied scoped occurrence events.
Every listed event must independently authenticate with a separately supplied,
source-bound anchor. This includes non-approval records and records whose altered
scope or occurrence time would otherwise remove them from the matching set.
Missing, invalid or source-mismatched event signatures make coverage unusable for
absence while the valid manifest remains AUTHENTICATED_COVERAGE. Receipts are not
substitutes for event authentication, and event delivery is not required for
retrospective coverage. A signed empty manifest can still qualify.
Any supplied approval counterexample prevents absence, even if unauthenticated.
Missing or invalid coverage stays NOT_ESTABLISHED. Negative findings concern only
that exact source/channel/actor/action/subject/interval, never unauthorized action
or general absence of approval. Coverage may be retrospective; it cannot create
earlier actor knowledge. Manifests commit to IDs, not detached event content;
event signatures independently authenticate contents.
The manifest itself attests only its producer's completeness assertion. Neither
external truth nor source honesty is established by these verification checks.

Authority diagnostics check exact credential, operation, resource, actor, source,
action, subject and channel. Only known authenticated records become approval or
revocation evidence. Expired approvals are marked; known scoped revocation causes
an explicit conflict, not a latest-record-wins grant. Revocation freshness and
final authority remain NOT_ESTABLISHED even with an apparently valid approval.
This deliberately does not infer a policy or a reauthorization precedence rule.

## Bounds and unsatisfied gates

Hard caps: 2,000,000 input bytes, 12 JSON nesting levels, 100,000 structure nodes,
4096 characters per string, 256 per key/label, 512 events, 2048 combined receipts
and manifests, 512 IDs per manifest, 2,000,000 serialized output bytes. File reads
reject symlinks in every component and nonregular files and use bounded reads
against growth races. No graph traversal, user-defined edges, executable rules or
arbitrary text rendering exists in v1; unknown edge fields fail closed. Replay
performs at most 512*2048 event/coverage scope checks, plus bounded parsing,
sorting and hashing. The operation caps are a work budget, not a hard wall-clock
or process-memory deadline. `tools/benchmark_evidence_state.py` measures three
runs of one deterministic 512-event/2048-edge synthetic case and reports bytes
and output digest; it is not a production throughput benchmark.

This layer is **not production-ready certification**. Unsatisfied release gates:

* Independent source onboarding/key custody and rotation/revocation protocols,
  adversarial signer audits, trustworthy receipt instrumentation and independent
  validation of completeness. No operator assertion alone closes these gates.
* Policy-version binding, trusted credential status horizons, delegation and
  reauthorization precedence, source-specific revocation freshness, and final
  authorization verification. No positive authority verdict is implemented.
* Multi-implementation canonical test vectors and interoperability certification;
  independent cryptographic/security review. Python output is the reference.
* Deployment-specific CPU/memory/deadline enforcement and load measurements under
  the actual host threat model. No remote/public processing endpoint is supplied.
* A reviewed public share schema and selective reproduction protocol for this
  evidence-state format. Local digests alone are not a safe sharing guarantee.

Existing incident-v2, Apache-2.0 and NOTICE remain unchanged. The earlier audit's
open gaps remain applicable to legacy incidents; this schema does not retroactively
upgrade them.

## Coverage member authentication regression verification (2026-10-23)

Test-first reproduction failed eight new member-authentication cases before the
fix. The corrected API and CLI reject coverage usability for modified kind,
authority scope, occurrence/observation/ingestion clocks, source, stripped or
invalid signatures and untrusted key IDs, preserving valid manifest authentication.
Signed empty manifests and authenticated non-approval members still qualify;
legitimate signed approvals prevent a negative finding.

Offline verification: full suite 237 passed, 3 skipped (prior 225 plus 12 new
cases); evidence-state/hardening/audit-repair/second-pass security tests 122
passed; clean-wheel release smoke passed with signed-member attack and legitimate
approval/empty-manifest controls. Skips require the unavailable optional
`agentrust_trace` package (two) or private DDC Radial checkout (one). No network
dependencies were fetched. These checks do not establish source honesty,
real-world completeness, or independent cryptographic certification.
