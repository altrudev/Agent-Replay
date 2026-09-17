# Authority revocation execution harness

This harness is a deterministic local execution test for the public authority-revocation case. It is **not** a production payment integration and does not contact external services.

It uses an in-memory authority state and payment ledger to exercise this sequence:

1. approval is issued while authority is active;
2. authority is revoked;
3. propagation toward the execution boundary is attempted, but no delivery acknowledgement is captured;
4. a stale execution decision permits execution after revocation;
5. the primary route is attempted and does not commit;
6. an alternate-route retry is exercised;
7. the alternate route produces one downstream synthetic effect.

## Expected-behavior basis

The harness supplies the following normative assertions as test inputs:

- after recorded revocation, `execution_permitted` is expected to be `false`;
- after that same revocation, `retry_permitted` is expected to be `false`;
- the downstream transfer is expected not to execute.

These are **harness policy assertions**, not independently authenticated policy truth. Agent Replay evaluates the supplied assertions and preserves that scope distinction.

The propagation event intentionally has no expected-state assertion. The harness records that propagation was attempted, but it does not manufacture a delivery acknowledgement. Therefore the result must retain an evidence gap: revocation being recorded is not proof that revocation reached the execution boundary.

## Reproduce

From the repository root:

```bash
python3 tools/authority_retry_harness.py \
  --events /tmp/authority-retry-events.jsonl \
  --result /tmp/authority-retry-harness.json

agent-replay reconstruct \
  /tmp/authority-retry-events.jsonl \
  --json \
  > /tmp/authority-retry-incident.json
```

The harness result should report:

```text
alternate_route_retry_exercised = true
primary_route_committed = false
downstream_effect_count = 1
revocation_delivery_acknowledgement_captured = false
production_integration = false
```

The Agent Replay reconstruction should identify `execution_decision` as the first provable divergence, preserve the alternate-route retry as a later divergence, and keep the propagation acknowledgement unresolved.

## Independently checkable after sanitization

A reviewer can independently check, without DDC:

- the Agent Replay commit used;
- the public harness source;
- the reproduction command above;
- the SHA-256 of the generated canonical event file;
- the resulting Agent Replay input/canonical hashes;
- the first provable divergence and causal relationships;
- whether the alternate-route retry was exercised;
- whether the propagation acknowledgement remains absent.

Proprietary DDC internals are not required for any of those checks.
