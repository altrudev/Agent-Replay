# APS authority reconstruction adapter

This adapter maps Agent Passport System (APS) pre-action evidence into an Agent Replay authority reconstruction without collapsing identity, authority, policy, and execution into a single actor claim.

## Pinned interoperability fixture

The regression contract is based on:

- repository: `Agent-Authority-Conformance/aps-conformance-suite`
- revision: `6e8b05b202d727ef18e84e100fc31db11f36529f`
- fixture family: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1`

The pinned family contains 13 cases:

`pass`, `caution`, `danger`, `block`, `expired-oracle`,
`tampered-oracle`, `wrong-signer`, `authority-denied`,
`sig-tampered`, `digest-mismatch`, `evidence-missing`,
`delegation-expired`, and `delegation-revoked`.

## Evidence model

Replay keeps these layers independent:

1. **Claimed actor** — the subject/issuer named by the action-intent receipt.
2. **Receipt signer** — the signer identity carried by the supplied receipt.
3. **Delegated authority** — the principal-rooted APS delegation path.
4. **Policy decision** — the gateway's pre-dispatch permit/deny result.
5. **Observed execution** — post-dispatch/post-execution evidence only.

A valid permit is never promoted into execution evidence.

## Cryptographic boundary

`agent_replay.aps.reconstruct_aps_fixture()` does not implement an
independent Ed25519 or EIP-712 verifier. It preserves the APS fixture's
external conformance outcome and reasons, and labels receipt identity
consistency separately.

This matters for negative fixtures. For example, `sig-tampered` can
preserve the claimed gateway identity while reporting that APS's fixture
oracle says the decision signature failed.

## Expected no-execution result

The current APS fixture is pre-dispatch and contains no post-execution
receipt/event. Therefore every pinned case must reconstruct:

```text
observed_execution: []
execution_status: NOT_OBSERVED
permit_is_execution: false
```

That empty result is intentional evidence, not a missing feature.

## Python API

```python
import json
from agent_replay.aps import reconstruct_aps_fixture

with open("pass.json", "r", encoding="utf-8") as fh:
    fixture = json.load(fh)

report = reconstruct_aps_fixture(fixture)
```

The returned document uses schema:

`agent-replay.aps-authority-reconstruction.v1`
