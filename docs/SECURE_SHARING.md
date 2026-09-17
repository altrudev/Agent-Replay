# Secure external evidence sharing

Agent Replay incident documents are evidence containers, not publication artifacts. They may contain raw evidence metadata, actor labels, timestamps, internal paths, customer identifiers, TRACE material, infrastructure details, or other confidential values.

For external sharing, use the allowlist-only export path:

```bash
agent-replay export-share incident.json \
  --radial radial.json \
  --agent-replay-commit <commit> \
  -o public-share.json
```

## Export boundary

The public bundle is constructed from an explicit allowlist. It does **not** copy arbitrary source fields and then attempt to redact them afterward.

Included:

- source incident/canonical SHA-256 values;
- event IDs, event kinds, parent relationships and mismatch fields;
- pseudonymized actor labels (`actor-1`, `actor-2`, ...);
- reconstruction status, confidence and evidence-completeness state;
- evidence-gap type/basis/effect fields;
- DDC Radial candidate IDs/titles/subjects/rationale/falsification text;
- DDC engine SHA-256 for provenance;
- Agent Replay commit identifier when supplied;
- a SHA-256 over the complete pre-hash public bundle.

Excluded:

- raw `evidence` objects;
- timestamps;
- original actor/service labels;
- TRACE evidence and keys;
- DDC engine path or source code;
- DDC feature vectors, scores and thresholds;
- absolute filesystem paths;
- infrastructure addresses;
- arbitrary unallowlisted fields.

The final bundle is also scanned for common bearer tokens, credential-shaped values, absolute `/home/...` paths, IP addresses and email addresses. A match fails closed rather than silently publishing the bundle.

## DDC Radial review of the sharing boundary

The export boundary is designed against these failure dimensions:

- **Representation:** the external artifact is a new, explicit public schema rather than a partial copy of the internal incident document.
- **Authority:** the exporter does not grant publication authority to arbitrary input fields; only allowlisted fields can cross the boundary.
- **Provenance:** source incident hashes, optional Agent Replay commit and DDC engine hash remain available without exporting source code or local paths.
- **Privacy:** actor identities, timestamps, raw evidence and infrastructure metadata are removed or pseudonymized.
- **Dependency:** the standalone Agent Replay core does not import or execute DDC to create the public bundle; an optional Radial JSON result is treated only as data.
- **Observability:** the bundle states what was omitted so a recipient cannot mistake sanitization for complete raw evidence.
- **Consequence:** export fails closed on detected sensitive patterns; it never falls back to an unredacted artifact.

## Sharing rule

Do not send raw incident JSON, raw Radial JSON, the DDC checkout, VPS paths, terminal transcripts, credentials, customer evidence, or private traces to an external reviewer unless that disclosure is separately intended and authorized.

For the canonical execution-time authority case, the fixture is synthetic, but the same export boundary should still be used so the demonstration exercises the production-safe disclosure path rather than a one-off manual redaction.
