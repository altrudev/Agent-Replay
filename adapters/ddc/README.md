# Agent Replay DDC Adapter

Optional DDC integration for Agent Replay.

The standalone Agent Replay core does **not** import or require DDC.

## Radial Frequency mode

Point the adapter at a local checkout of the private DDC repository:

```bash
export DDC_RADIAL_ROOT=/path/to/ddc
```

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
