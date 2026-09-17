# Authority revoked before execution

This fixture models an approval that was valid when issued, then revoked before an execution attempt.

Intended sequence:

1. approval is issued for a specific payment object;
2. authority is revoked and advances from `v17` to `v18`;
3. propagation toward the payment boundary is attempted, but no delivery acknowledgement is captured;
4. the agent attempts execution while the supplied evidence says authority is `REVOKED`;
5. the payment API records that the transfer executed.

The fixture is deliberately not a clean demo. It contains a real evidence gap: Agent Replay can prove the recorded revocation preceded the execution attempt and can prove the supplied execution assertion diverged, but it cannot prove that the payment boundary received the revocation because that acknowledgement is absent.

Run:

```bash
agent-replay reconstruct examples/authority-revoked-before-execution/events.jsonl
```

Expected findings:

- earliest provable divergence: `execution_attempt`;
- `execution_permitted`: expected `false`, observed `true`;
- `payment_executed` is explicitly downstream of the first divergence;
- primary evidence label: `payment-agent`;
- contributing evidence label: `payment-api`;
- evidence completeness: `INCOMPLETE` because `revocation_propagation` has no caller-supplied expected-state assertion;
- Agent Replay must not claim that the missing revocation-delivery acknowledgement proves the payment API did or did not receive the revocation.

The expected-state assertions are fixture inputs, not policy truth independently authenticated by Agent Replay. This case exists to test reconstruction, evidence boundaries, and execution-time qualification without turning Agent Replay into the authorization system itself.
