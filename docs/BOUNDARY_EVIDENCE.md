# Authenticated boundary evidence

Agent Replay remains an evidence reconstruction engine. Boundary proof support does not turn it into a policy engine or enforcement runtime.

## What this adds

An event may carry two optional signed evidence envelopes:

- `evidence.policy_proof`: binds the event's expected state to a signed policy assertion.
- `evidence.revocation_receipt`: proves that a named execution boundary signed a receipt for a specific revocation event before the execution event.

Both envelopes use Ed25519 and are verified only against keys explicitly present in a caller-supplied trust store.

## Trust store

The trust store is a JSON object:

```json
{
  "policy-authority-key": "<base64 raw Ed25519 public key>",
  "payment-boundary-key": "<base64 raw Ed25519 public key>"
}
```

CLI:

```bash
agent-replay reconstruct events.jsonl --trust-store trust.json --json
```

Install the optional verifier with:

```bash
pip install "agent-replay[proof]"
```

Without the optional verifier, proofs fail closed as `VERIFIER_UNAVAILABLE`.

## Policy proof

The signed policy payload must include:

- `policy_id`
- `policy_version`
- `authority_version`
- `event_id`
- `subject`
- `action`
- `authority_scope`
- `expected_sha256`
- optional `valid_from` and `valid_until`

`expected_sha256` is the Agent Replay JSON v1 digest of the event's exact `expected` object.

A valid signature alone is not enough. The event binding, expected-state digest, and validity window must also match.

## Revocation receipt

The signed receipt payload must include:

- `revocation_id`
- `authority_version`
- `execution_boundary_id`
- `received_at`
- `policy_id`
- `policy_version`
- `policy_sha256`
- `revocation_event_id`
- `revocation_sha256`
- `nonce`

The receipt must bind the canonical Agent Replay representation of the supplied revocation event, the exact signed policy payload, and the same authority version. `received_at` must be no later than the execution event and no earlier than the bound revocation event.

## Claim boundary

A verified policy proof establishes that the supplied expected state was signed by a key the caller explicitly trusted. It does not prove that the signer was legally or organizationally entitled to define that policy.

A verified receipt establishes that the trusted boundary key signed receipt of the bound revocation event by the stated time. It does not, by itself, authenticate the identity continuity between that boundary and every later execution event.

Receipt nonce replay detection is incident-local. Cross-incident replay prevention belongs to the issuing boundary or a persistent verifier.

## Canonicalization

Signed payloads use `AGENT_REPLAY_JSON_V1`:

- UTF-8 JSON
- object keys sorted lexicographically
- compact separators
- no Unicode normalization
- no floating-point values in signed payloads

This keeps representation differences explicit rather than silently normalizing them.

## DDC Radial role

DDC Radial remains advisory. It may identify stale authority, TOCTOU, replay, representation, identity, or receipt-binding hypotheses, but it does not grant authority and cannot upgrade an unverified proof to verified evidence.
