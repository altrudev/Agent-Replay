# Agent Replay DDC Adapter

Optional DDC integration for Agent Replay.

The standalone Agent Replay core does **not** import or require DDC.

## Radial Frequency mode

Point the adapter at a local checkout of the private DDC repository:

```bash
export DDC_RADIAL_ROOT=/opt/ddc-approved
```

**Operator-enrolled source required.** For code execution, the adapter now
requires a root-owned, group/world-nonwritable DDC checkout and its `src`
directory and every file/importable module within it, plus a root-owned,
group/world-nonwritable exact lowercase SHA-256
for `src/radial_frequency_v10.py` at
`/etc/agent-replay/ddc-radial.sha256` (the parent directory must also be
root-owned). Installation and rotation must be performed by a trusted operator,
not by the model or the calling client. An ordinary writable development
checkout or an unprovisioned pin will fail closed. Validate all imported
dependencies and interpreter search paths before granting the runtime
privileges; this pin alone does not constitute independent attestation.
No installation or key provisioning is performed by the adapter.

Install the optional adapter:

```bash
python -m pip install -e ./adapters/ddc
```

Run DDC Radial directly against an Agent Replay incident document:

```bash
agent-replay reconstruct examples/refund-750/events.jsonl --json \
  | agent-replay-ddc-radial
```

Or connect it through the generic Agent Replay DDC bridge:

```bash
export AGENT_REPLAY_DDC_CMD=agent-replay-ddc-radial
agent-replay-ddc verify examples/refund-750/events.jsonl
```

## Semantics

The adapter maps Agent Replay's canonical event graph into DDC Radial Frequency nodes and edges.

Radial structural properties must come from supplied evidence. Actor names, event names, and mismatch labels are not silently promoted into authority domains, state independence, atomicity, or consequence claims.

Simple one-parent events may place edge hints directly in `evidence.radial`. For a child with multiple parents, use explicit per-parent overrides so different incoming relationships are not collapsed into one semantic edge:

```json
{
  "evidence": {
    "radial": {
      "authority": "payment-boundary",
      "edges": {
        "approval_issued": {
          "relation": "authorizes",
          "time_gap": 0.4,
          "independently_mutable": true,
          "shared_atomic_boundary": false,
          "freshness_bound": false,
          "context_bound": true
        },
        "authority_revoked": {
          "relation": "depends_on",
          "time_gap": 0.2,
          "independently_mutable": true,
          "shared_atomic_boundary": false,
          "freshness_bound": false,
          "context_bound": true
        }
      }
    }
  }
}
```

Per-parent hints override flat edge hints only for that parent. Malformed `radial.edges` evidence fails closed.

DDC Radial output is intentionally **non-authoritative**. Its hypotheses are `CANDIDATE` findings and include falsification tests. The adapter therefore returns:

```json
{
  "adapter_schema": "agent-replay.ddc-radial.v1",
  "authoritative": false,
  "disposition": "CANDIDATE_FINDINGS",
  "hypotheses": []
}
```

It does **not** convert Radial hypotheses into ALLOW/BLOCK decisions, blame, or expanded execution authority.

## Boundary

Agent Replay remains responsible for deterministic incident reconstruction from supplied evidence.

DDC Radial is optional second-order analysis used to ask:

- what structural fault classes fit the reconstructed incident?
- which relationships deserve falsification testing?
- where could the reconstruction or underlying system still have blind spots?

Deleting `adapters/ddc/` leaves Agent Replay fully functional.
