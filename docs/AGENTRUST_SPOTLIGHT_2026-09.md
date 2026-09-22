# AgenTrust Spotlight Capture — September 2026

This pack is intentionally narrow. It demonstrates exactly what the merged Agent Replay TRACE integration verifies, one fail-closed rejection, and the boundary it does **not** cross.

## Pinned product state

- Agent Replay release: `0.6.0`
- TRACE dependency in `pyproject.toml`: `agentrust-trace==0.9.0`
- Spotlight preparation branch base: `1f4db7a12e8ddf8853c2533f08f8252f7efbe326`
- Product: <https://github.com/altrudev/Agent-Replay>

The capture script records the exact checked-out commit and installed package versions in the generated manifest. Those runtime values, not this prose, are the publication evidence.

## DDC Radial publication invariants

The spotlight must preserve these distinctions:

1. **Record validity is not incident truth.** A valid TRACE record proves only the verification scope reported by the adapter.
2. **Actor identity is not authority.** No screenshot should collapse subject/signer identity into delegated authority.
3. **Policy decision is not execution.** Pre-dispatch authorization must not be presented as proof of a post-dispatch effect.
4. **Transcript hash is not transcript-to-incident binding.** The merged integration does not independently prove that Replay's incident input is the transcript committed by `tool_transcript.hash`.
5. **External effect is not established by TRACE verification.** The valid screenshot must not imply that an external system changed state.
6. **Rejection fails closed.** The rejected case mutates a signed field after signing; the real TRACE verifier must reject it.
7. **Provenance must be visible.** Every capture must show the current git commit and package versions.
8. **No borrowed oracle.** The demo reports the verifier result it actually obtains; it does not import an expected label and present it as a measured result.

## Capture procedure

Run from a clean checkout of the spotlight branch on a DSR worker:

```bash
python -m pip install -e '.[trace]'
python scripts/agentrust_spotlight_demo.py
cat artifacts/agentrust-spotlight/spotlight-manifest.json
```

Then run the relevant regression tests:

```bash
python -m pytest -q tests/test_trace.py tests/test_trace_real_verifier.py
```

Do not capture screenshots until both commands pass on the same checkout.

## Screenshot 1 — valid TRACE

Capture the terminal output beginning at `VALID TRACE` and include:

- `Status: VERIFIED`
- record SHA-256
- trusted-key SHA-256
- Agent Replay version
- `agentrust-trace` version
- git commit
- the boundary lines:
  - `Transcript-to-incident binding: NOT_VERIFIED`
  - `Post-execution effect: NOT_ESTABLISHED_BY_TRACE_VERIFICATION`

Suggested annotation:

> Valid signed TRACE record verified with an independently supplied trusted issuer key. Agent Replay preserves the boundary: this does not prove transcript-to-incident binding or an external post-execution effect.

## Screenshot 2 — rejected TRACE

Capture the `REJECTED TRACE` section and include:

- `Status: REJECTED`
- rejection exception class
- mutated record SHA-256
- same package versions and git commit

Suggested annotation:

> The record was signed, then its subject was changed. The real TRACE verifier rejects the modified record; Agent Replay does not downgrade or reinterpret the failure.

## What not to show

Do not describe the valid record as:

- a complete incident proof,
- proof that a tool transcript matches Replay input,
- proof of hardware attestation,
- proof of transparency-ledger inclusion,
- proof that an external effect occurred.

Those claims exceed the merged integration.

## AgenTrust delivery package

Send:

- one valid annotated screenshot,
- one rejected annotated screenshot,
- `spotlight-manifest.json`,
- current commit SHA,
- Agent Replay and `agentrust-trace` versions,
- preferred product link: <https://github.com/altrudev/Agent-Replay>,
- explicit permission for AgenTrust to reproduce the supplied demo/screenshots in the spotlight.

The demo artifacts under `artifacts/agentrust-spotlight/` are run outputs and should not be committed by default. Review them for sensitive values before sharing.
