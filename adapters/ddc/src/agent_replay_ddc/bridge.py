import json
from agent_replay import strict_json
import os
import shlex
import subprocess


class DDCAdapterError(RuntimeError):
    pass


def run_ddc(incident: dict) -> dict:
    command = os.environ.get("AGENT_REPLAY_DDC_CMD")
    if not command:
        raise DDCAdapterError(
            "AGENT_REPLAY_DDC_CMD is not set. "
            "Agent Replay core remains fully functional without DDC."
        )

    proc = subprocess.run(
        shlex.split(command),
        input=strict_json.dumps(incident),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    if proc.returncode != 0:
        raise DDCAdapterError(
            f"DDC adapter command failed with exit code {proc.returncode}: "
            f"{proc.stderr.strip()}"
        )

    try:
        result = strict_json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DDCAdapterError("DDC adapter returned invalid JSON") from exc

    if not isinstance(result, dict):
        raise DDCAdapterError("DDC adapter result must be a JSON object")

    return result
