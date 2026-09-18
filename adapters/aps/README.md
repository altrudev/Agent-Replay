# APS authority reconstruction adapter

Agent Replay v0.6 maps APS pre-action evidence into an authority-safe reconstruction without collapsing identity, delegation, policy, and execution.

## Validated fixture line

The adapter regression suite vendors the exact 13 cases from:

- repository: `Agent-Authority-Conformance/aps-conformance-suite`
- revision: `6e8b05b202d727ef18e84e100fc31db11f36529f`
- family: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1`

This revision identifies what the adapter was validated against. It is **not** automatically asserted as provenance of a user-supplied APS file.

## Evidence layers

Replay preserves five boundaries:

1. claimed actor / receipt signer,
2. delegated authority chain,
3. policy decision,
4. structural binding across action, receipt and delegation references,
5. execution evidence.

External APS conformance outcomes are preserved under `external_conformance`. Replay separately records whether it independently verified cryptography; v0.6 reports `NOT_VERIFIED` for Ed25519/EIP-712 verification.

## Execution rule

A permit is not execution evidence.

Execution states are:

```text
NO_EXECUTION_EVIDENCE
EXECUTION_EVIDENCE_UNBOUND
EXECUTION_EVIDENCE_PARTIALLY_BOUND
EXECUTION_BOUND_TO_ACTION
```

An execution event is only counted as bound when its `action_ref` matches the reconstructed action and its actor does not contradict the claimed actor. This still does not make the event cryptographically authenticated.

## Usage

```bash
agent-replay reconstruct fixture.json --format aps
agent-replay reconstruct fixture.json --format aps --json -o aps-incident.json
agent-replay export-share aps-incident.json -o aps-public-share.json
```

The optional DDC adapter also accepts `--format aps` and maps the reconstruction into a delegation → intent → policy → execution evidence graph for non-authoritative Radial review.
