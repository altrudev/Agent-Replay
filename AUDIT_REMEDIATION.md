# DDC/Frequency audit repairs — 2026-10-22

Implemented on fix/ddc-frequency-audit-2026-10-22, without runtime model dependencies.

- Comparisons distinguish MATCH, MISMATCH, NOT_OBSERVED, NOT_COMPARABLE.
  Presence is determined by object membership: explicit null remains evidence.
  Timeline INCOMPLETE takes precedence when required observations are missing;
  proven mismatches remain in divergences even on an incomplete event.
- First divergence is an earliest-time causal frontier. Independent ties yield
  first_divergence_order=AMBIGUOUS, a null singular field and a full frontier set.
  Parent-before-child takes precedence within tied timestamps, including through
  intermediate non-divergent events. Stable serialization is not proof of order.
- JSON parsing rejects recursive duplicate keys, non-finite constants and numeric
  overflow. Serialization rejects non-finite numbers. OTLP doubleValue requires
  a finite numeric value rather than permissive string coercion.
- Reproduction separately checks exact_input_sha256; byte differences alone do not
  invalidate canonical semantic reproduction. Source positions are provenance,
  not canonical identity. Frontier membership participates in reproduction.
- Actor roles PRIMARY/CONTRIBUTING/DOWNSTREAM are deprecated association labels,
  not authenticated identities or responsibility. Confidence is structural only.
- Each causal ancestor list is limited to 128 entries, with exact total count,
  truncation flag and output limit. Global causal_ancestor_output_scope is
  TRUNCATED when applicable, including in public shares. Full graph traversal
  preserves relationship semantics with linear working memory; runtime on dense
  or long graphs may remain quadratic. No transitive closure cache is retained.
- DDC requires operator enrollment with DDC_RADIAL_ROOT and DDC_RADIAL_SHA256.
  Missing/mismatched pins or group/world-writable source/root/src fail closed.
  The source digest binds the compiled bytes, not dependencies imported by that
  source. DDC executes trusted operator code; it is not a hostile-code sandbox.

## Open architectural gaps

Three independent clocks (event time, observation time, ingestion time), actor
instance horizons, authenticated coverage, and policy/tool continuity require a
larger evidence schema/ruleset change. They are not established by these repairs.
Python JSON equality/canonicalization is not yet a language-independent canonical
specification. Source authenticity and actor authentication remain unestablished.
A portable claims manifest and complete resource/time budgets remain future work.
The optional private DDC and TRACE integrations cannot be independently verified
without their locally installed artifacts. No external artifacts were retrieved.

## Second-pass repairs — 2026-10-23

- Reproduction distinguishes unavailable legacy scope from observed differences.
  Missing frontier or ancestor metadata produces null checks, explicit
  unavailable_checks and PARTIAL_CANONICAL_SEMANTICS identity scope. Matching
  legacy evidence is INCOMPLETE, with core_reproduced=false; canonical digest
  equality alone does not establish the newer reconstruction claims. Known
  canonical, singular-divergence and causal-chain drift still yields DRIFTED;
  current incidents with matching complete scope remain REPRODUCED.
- Legacy public shares omit absent optional frontier/order/ancestor-scope fields
  rather than inventing an empty frontier or emitting schema-invalid null enums.
  Regression validates the public schema and checks pseudonymization/value omission.
- Failed execution of correctly pinned DDC source restores the previous module
  entry (or removes the partial module) and restores sys.path. Source pin and
  permissions checks remain enforced; this is cleanup, not execution isolation.
- Test-first regression used an actual incident emitted by tracked v0.6.0 code
  at 61a8c61379f46526245d465504eb82a2e20785e2 from synthetic evidence. Before
  fixes: 4 failed, 5 passed, reproducing all three reported defects, including
  both prior-module states. No external artifacts or network were used.

Final validation (temporary files confined to this clone via TMPDIR):
- `TMPDIR="$PWD/.audit-work/tmp" python3 -m pytest -q`: 150 passed, 3 skipped.
- `TMPDIR="$PWD/.audit-work/tmp" python3 tools/release_smoke.py`:
  AGENT REPLAY RELEASE SMOKE PASS (offline clean-wheel check).
- `git diff --check`: passed.
These results do not establish optional private-integration behavior beyond the
installed test scope. No commit or push was performed.
