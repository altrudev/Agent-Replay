# Agent Replay DDC Adapter

Optional DDC adapter for Agent Replay.

The Agent Replay core does not import or require this package.

## Boundary

The adapter:

1. reconstructs the incident using Agent Replay,
2. serializes the incident as JSON,
3. sends JSON to a configured DDC command over stdin,
4. accepts one JSON object back over stdout,
5. never permits DDC to mutate the underlying evidence.

Set the command:

```bash
export AGENT_REPLAY_DDC_CMD='python /path/to/ddc_agent_replay_adapter.py'
```

Then run:

```bash
agent-replay-ddc verify examples/refund-750/events.jsonl
```

Expected DDC-side response:

```json
{
  "adapter_schema": "agent-replay.ddc-result.v1",
  "disposition": "ALLOW",
  "findings": [],
  "engine_version": "..."
}
```
