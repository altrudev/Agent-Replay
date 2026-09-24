# Execution-boundary research comparison — 2026-09-24

Author: Valentyn Rukhaylo / Altru.dev. Review artifact; no runtime-enforcement or novelty certification.

## Pinned DDC evidence

- Agent Replay main: `7601b7025d4683a35c8fc403b78420811362535f`.
- ATC main: `f7f12e479c580cb20c556aaccf3106d1ec568f2a`.
- ATC earliest reachable commit: `9f10df2c30c7922a60e15a9640751acf05b33c99`, author date September 11, 2026, 19:34:56 UTC. Its README already asks whether authorization produced an acceptable transition from the evaluated predecessor.
- Initial verifier: `26087088539e70e96b327d301952398ab762e13d`, September 11, 19:35:06 UTC. Inspected code requires successor evidence and an exact expected successor, with an indeterminate outcome for missing evidence.
- Later commit-boundary probe: `cd676665c4143ad616bd0bae2124ae32e5105b7c`, September 14 UTC; strengthened `502d27e5fea506fab708bcdec48f14b60ab3f2eb`; T8/T9 extension `74f508a25e1622136034d4e6a4a18e63fb837c4f`, September 20.

These are Git history dates, not independently established first-publication dates. Earlier DDC work elsewhere was not dated in this review. This repository alone does not establish chronological priority over the September 10 paper. The earlier briefing used “prior art” as an overlap flag; legal priority has not been determined.

## EBL-Core comparison

Source: Wu et al., [From Intent to Execution Grant](https://arxiv.org/abs/2609.11596), v1 submitted September 10, 2026, 14:21:45 UTC; [PDF](https://arxiv.org/pdf/2609.11596), especially §3.1. Preprint, not an adopted standard.

EBL-Core separates a decision contract, an execution grant and redemption. It requires validation, grant consumption and the protected transition to be linearized relative to decision-relevant state. It explicitly does not establish correct external outcomes. Separate verification concerns decision derivation, not independent observation of real-world consequences.

| Dimension | EBL-Core | Inspected ATC reference |
|---|---|---|
| Action/policy binding | Release and redemption bindings | Compares authorized/executed action and policy digests |
| Changing state | Linearization requirement at protected transition | Compares authorized/observed predecessor; supplied freshness flags |
| Outcome assurance | Correct external outcome not established | Requires supplied trusted, fresh successor and exact predicate |
| Independent evidence | Decision verification | Observer trust remains a relying-party input |

Assessment: overlapping boundary concerns, complementary assurance scopes. ATC is not itself an atomic execution gate. Neither a matching digest nor a supplied trust flag authenticates an observer. Do not describe EBL-Core as ignoring the external-effect boundary. Its ancillary Python files could not be retrieved through the available web reader; no implementation audit or reproduction of its results is claimed.

## Existing coverage and remaining gaps

ATC already has predecessor mismatch, policy skew, replay, missing successor, wrong successor and unknown observer-trust tests in `tests/test_verifier.py`. Reusing these is preferable to adding duplicates under new research names. Its exact-digest model does not by itself establish that every relevant plan dependency was captured. Its verifier also consumes upstream authority assumptions rather than validating natural-language instruction provenance.

Agent Replay's `reconstruct_records` compares caller-supplied expectations with observations and retains supplied provenance. It is a forensic consumer, not a runtime authorizer. It cannot infer an undisclosed policy or prove the authenticity of caller-supplied authority labels.

Open PRs inspected: Agent Replay #16 (evidence model), #17 (provenance), #7 (missing-observation semantics), #9 (hosted service), ATC #3 (provenance). This change leaves them untouched. In particular, new tests do not depend on missing-observation semantics or pretend the pending evidence model is merged.

## Added regression scenarios

Original synthetic tests in `tests/test_research_boundaries.py`; no external code or datasets copied.

1. Fresh memory r4 with execution still using plan dependency r3: reconstruct the execution mismatch.
2. Replanned r4 control: no mismatch under the supplied expectation.
3. Untrusted instruction carried through 1, 3 and 12 summary/retry/handoff steps: retain origin and reconstruct the explicitly evidenced authority mismatch.
4. For each repetition count, remove the normative assertion: remain unassessed and incomplete, never infer authorization from repetition.
5. A separately supplied later user-grant control: distinguish it from the tool suggestion, while retaining the caller-assertion warning.

Motivation and attribution:
- Chen, Wang and Brinton, [PlanFence](https://arxiv.org/abs/2609.03340), v1 September 3, 2026. Fresh information does not alone validate an older plan; dependency-scoped revalidation is the relevant comparison.
- Guo et al., [SARA](https://arxiv.org/abs/2608.27146), v1 August 27, 2026. Action origin and execution authority must remain distinct; history repetition must not promote authority.

These six parametrized test cases exercise Replay's current reconstruction contract, not PlanFence/SARA prevention, independent authentication, automatic dependency discovery, or a new authority policy engine. Upstream performance claims were not reproduced.

## Next bounded experiment

Use a disposable effect store and independent observer to test grant consumption followed by absent, wrong or delayed effect. Keep the outcome unknown until adequate evidence arrives; preserve the original decision-time view. A real EBL-Core adapter requires retrieved, reviewed upstream code and explicit licensing checks before integration. Do not turn a schematic comparison into a claimed cross-system conformance result.

## Verification performed

Python 3.12, pytest 9.1.1, isolated local environment:

- Agent Replay: `PYTHONPATH=src python -m pytest tests/test_research_boundaries.py tests/test_reconstruct.py -q` — 19 passed, including six new cases and 13 existing reconstruction cases.
- ATC pinned main: `PYTHONPATH=. python -m pytest tests/test_verifier.py -q` — 14 passed.

No production code changed. No full release-suite, external paper reproduction, governed worker, or deployment result is claimed. No GitHub Actions were used.
