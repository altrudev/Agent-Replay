# APS authority reconstruction adapter

This adapter maps Agent Passport System (APS) evidence into Agent Replay without collapsing claimed identity, receipt signer, delegated authority, policy decision, and execution into one actor claim.

## Pinned interoperability fixture

The regression contract is based on:

- repository: `Agent-Authority-Conformance/aps-conformance-suite`
- revision: `6e8b05b202d727ef18e84e100fc31db11f36529f`
- fixture family: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1`

All 13 upstream cases are vendored under `tests/fixtures/aps/oracle-safety-check-v1/` and are exercised directly by the release test suite.

## Evidence model

Replay keeps these layers independent:

1. **Claimed actor** — the actor named by the action-intent receipt.
2. **Signer claim** — the signer identity carried by a supplied receipt.
3. **Delegation structure** — principal root, delegation continuity and leaf binding.
4. **Policy decision** — the gateway's pre-dispatch permit/deny result.
5. **Execution evidence** — post-dispatch evidence only, graded by structural binding.

A valid permit is never promoted into execution evidence.

## Provenance boundary

The adapter revision it was tested against is not treated as provenance for arbitrary input.

Every reconstruction separates:

```text
adapter_tested_against
input_provenance
external_conformance
```

If the caller does not independently supply repository/revision/path provenance, input provenance remains `UNKNOWN`. The exact input bytes are still bound by SHA-256.

## Structural binding

Replay independently checks the structure supplied in the APS envelope:

```text
intent.action_ref == decision.action_ref
decision.prev == intent.receipt_id
intent.delegation_ref == decision.delegation_ref == leaf.delegation_id
delegation parent chain is continuous
```

The aggregate result is:

```text
COMPLETE | PARTIAL | BROKEN
```

This is structural evidence only. It is not independent cryptographic verification.

## Execution evidence grades

Execution evidence is monotonic:

```text
NOT_OBSERVED
EVIDENCE_PRESENT_UNBOUND
ACTION_BOUND
ACTOR_BOUND
```

An event must bind to the intent `action_ref` before it can become action-bound execution evidence. It must also name the claimed actor before it can become actor-bound. The adapter still reports cryptographic execution authentication as `NOT_VERIFIED`.

## Cryptographic boundary

`agent_replay.aps.reconstruct_aps_fixture()` does not independently verify Ed25519 or EIP-712 signatures. APS conformance outcomes are retained under an explicit external-conformance scope and never relabeled as Replay cryptographic verification.

## Current pinned fixture result

The current APS fixture is pre-dispatch and contains no post-execution event. Therefore every pinned case reconstructs:

```text
execution.status: NOT_OBSERVED
permit_is_execution: false
```

That empty execution result is intentional evidence discipline, not a missing feature.

## CLI

```bash
agent-replay reconstruct pass.json --format aps
agent-replay reconstruct pass.json --format aps --json
```

APS JSON is also auto-detected when the envelope contains intent, decision and delegations.

Safe external sharing is supported:

```bash
agent-replay export-share aps-reconstruction.json -o aps-public-share.json
```

DIDs, raw receipts, raw delegations and raw execution events are omitted from the public APS representation.

## DDC Radial

The optional DDC adapter can review APS reconstruction structure:

```bash
agent-replay-ddc review pass.json --format aps
```

Radial receives only the evidenced authority/delegation/receipt relationships. It remains non-authoritative and cannot upgrade Replay evidence.

The returned reconstruction schema is:

`agent-replay.aps-authority-reconstruction.v1`
