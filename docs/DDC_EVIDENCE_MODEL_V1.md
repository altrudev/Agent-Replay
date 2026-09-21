# Agent Replay — DDC Evidence Model v1

Agent Replay's core forensic question remains:

> What happened, where did execution first diverge, and what evidence supports that conclusion?

DDC Evidence Model v1 adds a second, separate reconstruction question:

> Given only the evidence available to this actor at that moment, plus evidence it was required to obtain, was the next action defensible?

These are intentionally separate assurance objects.

## Why

A later record can establish that an event occurred at 10:01 even when the actor did not receive that evidence until 10:08. A retry at 10:05 must therefore not be judged as if the actor already knew the later fact.

Agent Replay preserves:

- event time,
- evidence creation time,
- evidence availability time,
- decision time,
- actor-specific evidence state,
- required evidence,
- actually consulted evidence,
- claim-scoped source authority,
- provenance and transformation lineage,
- causal provenance,
- branch identity,
- contradictions,
- unresolved assumptions.

## Current implementation boundary

The ddc_evidence_model projection is opt-in through caller-supplied evidence.ddc_evidence metadata. Existing Agent Replay inputs remain valid.

Agent Replay currently preserves and reports these boundaries; it does not independently authenticate caller-supplied DDC metadata unless a separate adapter explicitly performs that verification.

The projection does not turn later evidence into contemporaneous evidence and does not treat a complete-looking action lineage as proof of downstream consequence.

## Invariants

- chronology is not causality;
- dispatch is not consequence;
- each transition earns its own certainty;
- observation is not reconstruction;
- later truth is not retroactive knowledge;
- confidence is scoped to a claim and evidence boundary;
- unknown is a valid result;
- contradictions remain visible;
- retries and alternate paths remain separate branches;
- truthful incompleteness is preferable to false completeness.

## Attribution

Agent Replay and the broader DDC architecture are designed and developed by **Valentyn Rukhaylo / Altru.dev**.

The evidence-model direction in this release was materially sharpened through Valentyn Rukhaylo's public technical engagement with **Jason McGill**, particularly around downstream consequence boundaries, contemporaneous versus later evidence, the three-clock model, actor-specific evidence horizons, and consequence versus decision reconstruction.

Additional DDC Radial analysis extended those insights into required-versus-consulted evidence, causal evidence provenance, evidence-channel adequacy, post-action contamination, and branch preservation.