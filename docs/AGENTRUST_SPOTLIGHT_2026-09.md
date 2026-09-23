# AgenTrust Spotlight Capture — September 2026

This pack is intentionally narrow. It demonstrates exactly what the merged Agent Replay TRACE integration verifies, one visible fail-closed rejection, additional adversarial rejection checks, and the proof boundaries it does **not** cross.

## Pinned product state

- Agent Replay release: `0.6.0`
- TRACE dependency: `agentrust-trace==0.9.0`
- Spotlight preparation branch base: `1f4db7a12e8ddf8853c2533f08f8252f7efbe326`
- Product: <https://github.com/altrudev/Agent-Replay>
- Publication runtime constraint set: `docs/agentrust-spotlight-runtime-constraints-py314.txt`

The capture script records the exact checked-out commit, Python/runtime information, the full installed package inventory, and a SHA-256 fingerprint of that inventory. Runtime evidence, not this prose, is authoritative for the captured run.

## Publication invariants

The spotlight must preserve these distinctions:

1. **Record validity is not incident truth.** A valid TRACE record establishes only the verification scope reported by the adapter.
2. **Actor identity is not authority.** Subject/signer identity must not be collapsed into delegated authority.
3. **Policy decision is not execution.** Pre-dispatch authorization is not proof of a post-dispatch effect.
4. **A signed transcript commitment is not transcript-to-incident binding.** The demo deliberately includes a valid signed `tool_transcript.hash`, but Agent Replay does not independently prove that its incident input is the transcript represented by that hash.
5. **External effect is not established by TRACE verification.**
6. **Rejection fails closed.** The visible rejected case mutates a signed subject after signing. Additional adversarial checks mutate the signed transcript hash and use the wrong caller-supplied trusted key.
7. **Provenance must be visible.** Capture the exact git commit, product/verifier versions, Python runtime, and environment package fingerprint.
8. **Freshness must not be confused with reproducibility.** Each run generates a fresh key and current `iat`, so record/key hashes intentionally change. Source revision and environment are recorded; bit-for-bit reproducibility is not claimed.
9. **No borrowed oracle.** The demo reports verifier outcomes it actually obtains.
10. **Proof horizon is explicit.** Verification stops before transcript-to-incident equivalence, hardware provenance, transparency inclusion, delegated authority, and external-effect claims.

## Why the transcript commitment is present

The valid TRACE specimen contains a synthetic one-call `tool_transcript` commitment. This is deliberate.

The demo proves that the commitment is inside the signed and verified TRACE record. It does **not** supply an incident transcript to Agent Replay and therefore does not evaluate whether Replay input equals the transcript committed by that hash.

Expected manifest state:

```text
transcript_commitment_presence = VERIFIED_AS_SIGNED_FIELD
transcript_to_incident_binding = NOT_VERIFIED
binding_evaluated = false
```

That is the exact boundary AgenTrust asked us to keep clear.

## Capture procedure

Run the bounded capture orchestrator from a clean checkout of the spotlight branch:

```bash
python3 scripts/agentrust_spotlight_capture.py
cat artifacts/agentrust-spotlight/spotlight-manifest.json
```

The orchestrator removes any prior spotlight venv, creates a fresh `.spotlight-venv`, installs the TRACE verifier through the publication runtime constraint set, runs:

```text
tests/test_trace.py
tests/test_trace_real_verifier.py
tests/test_agentrust_spotlight_demo.py
```

and then executes the publication demo from that same environment.

Do not install into the host Python environment, do not bypass PEP 668, and do not capture screenshots unless the orchestrator exits successfully on the same immutable revision used for the screenshots.

## Screenshot 1 — valid TRACE

Include:

- `Status: VERIFIED`
- record SHA-256
- trusted-key SHA-256
- signed transcript commitment
- Agent Replay version
- `agentrust-trace` version
- git commit
- Python version
- environment packages SHA-256
- `Fresh artifacts each run: YES`
- the boundary lines:
  - `Signed transcript commitment present: VERIFIED_AS_SIGNED_FIELD`
  - `Transcript-to-incident binding: NOT_VERIFIED`
  - `Post-execution effect: NOT_ESTABLISHED_BY_TRACE_VERIFICATION`

Suggested annotation:

> Valid signed TRACE record verified with an independently supplied trusted issuer key. The record contains a signed transcript commitment, but Agent Replay does not claim that this establishes transcript-to-incident binding or an external post-execution effect.

## Screenshot 2 — rejected TRACE

Include:

- `Status: REJECTED`
- rejection exception class
- mutated record SHA-256
- same package/runtime provenance shown for the valid case

Suggested annotation:

> The record was signed, then its subject was changed. The real TRACE verifier rejects the modified record; Agent Replay does not downgrade or reinterpret the failure.

The additional transcript-hash-tamper and wrong-trusted-key checks should also report `REJECTED` in the terminal/manifest, but they do not need separate screenshots.

## What not to claim

Do not describe the valid record as:

- a complete incident proof,
- proof that a tool transcript matches Replay input,
- proof of hardware attestation,
- proof of transparency-ledger inclusion,
- proof of delegated authority,
- proof that an external effect occurred,
- or a byte-for-byte reproducible artifact.

Those claims exceed the demonstrated proof horizon.

## AgenTrust delivery package

Send:

- one valid annotated screenshot,
- one rejected annotated screenshot,
- `spotlight-manifest.json`,
- exact commit SHA,
- Agent Replay and `agentrust-trace` versions,
- environment package fingerprint,
- preferred product link: <https://github.com/altrudev/Agent-Replay>,
- explicit permission for AgenTrust to reproduce the supplied demo/screenshots in the spotlight.

The run artifacts under `artifacts/agentrust-spotlight/` are generated evidence and should not be committed by default. Review them before sharing.
