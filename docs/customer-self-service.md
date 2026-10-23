# Customer-operated local self service (0.6.0)

This release includes a working Apache-2.0 local customer dashboard and reusable
standard-library backend. No hosted account or vendor enrollment is needed.
Linux/POSIX is required (directory descriptors, `O_NOFOLLOW`, `flock`, `/proc`).
Use a local filesystem, not a network share. Python 3.10+ is required.

Install the local release with `python3 -m pip install .` in your environment,
then start it yourself:

```sh
agent-replay customer serve --workspace "$HOME/my-replay-workspace"
```

`start` is an alias for `serve`. Choose a new directory under a trusted private
parent, never `/tmp` or another world-writable ancestor. Existing workspace roots
must be owned by you and mode 0700. The server creates only the final directory;
its parents must already exist. It rejects symlink components and traversal.
No administrator account, global source enrollment or cryptographic commands
are needed. The terminal prints a random-port **127.0.0.1** URL with a one-use
session capability in its fragment. Open the complete URL. Treat it as a local
session secret. It is not a signing key. Reload works using the HttpOnly local
session cookie. Restart produces a fresh link and invalidates the old session.

1. Home explains the three steps and offers offline diagnostics and Stop.
2. Sources & trust enrolls a source you own and generates a random 32-byte local
   key. Source names are case-sensitive. No independent verifier enrollment is
   available. Rotation and explicit permanent revocation are available here.
3. Import evidence accepts evidence-state v1 (2,000,000 UTF-8 bytes), incident
   JSONL, OTLP JSON or APS fixtures (32,000,000 bytes). Choose the format explicitly.
   “Load synthetic example” provides an immediately usable empty-scope coverage
   example. Enroll `demo-audit` to attest that synthetic source.
4. “Analyze supplied claims” runs validation and analysis with **no anchors**.
   Supplied signatures are preserved but do not implicitly become trusted.
5. For your own origin observations only, choose your source and review the exact
   proposal. Coverage signing is off by default and needs explicit selection.
   Review shows the input digest, context, entire decision scope/horizon, array
   indices and complete proposed records. Adding a key ID changes event bindings;
   your unsigned receipts are explicitly rebound in this proposal. Third-party
   receipt bindings or preexisting trust fields cannot be overwritten. Confirm
   ownership and every listed record, context and horizon before signing.
   The preview is bound to both the exact uploaded bytes and current key.
6. Results displays detailed evidence states, coverage warnings and key provenance.
   Saved reports can be verified locally; retired keys require the separate
   historical-verification checkbox. Summary export requires consent and omits
   raw evidence, source names, keys, timestamps and detailed findings. Digests and
   report IDs can still correlate private information. Review before sharing.
7. Stop from Home or Ctrl-C. No scheduler, background polling, telemetry, external
   assets, model dependencies or automatic outgoing requests are implemented.

`agent-replay customer init --workspace PATH` initializes without starting HTTP.
`customer status` and `customer diagnostics` inspect an offline workspace. The
workspace lock permits one process at a time; these commands cannot open a workspace
already served. Diagnostics is also available inside the running dashboard.

## Trust glossary and lifecycle

- **SELF_ATTESTED**: local source enrollment based on your assertion of ownership.
- **CUSTOMER_ATTESTED**: records signed after your explicit review. Signing a
  third-party claim cannot make it independently verified; use analyze-as-supplied.
- **CUSTOMER_SOURCE_AUTHENTICATED**: exact coverage passes the existing source,
  membership, event authentication, scope and horizon checks against your own key.
  This authenticates a producer's completeness assertion, not external truth.
- **SUPPLIED_CLAIMS / SUPPLIED_ASSERTION**: evidence analyzed without implicit trust.
- **EXTERNAL_VERIFIED**: requires independent verifier provenance. Not available
  through customer enrollment. **No independent certification badge is delivered.**
- **KNOWN**: trusted receipt assertion of prior delivery/consultation, not proof of
  comprehension. **MAYBE_AVAILABLE**, **LATER_OBSERVED**, and **NOT_ESTABLISHED**
  preserve uncertainty. Identity, authority and causality remain unestablished.

Rotation marks the previous active key RETIRED and retains its private file.
New attestations only use the active key. Historical verification is optional and
reproduces the saved document with the report's original key set, without changing
its original provenance. Revocation requires acknowledgement of permanent deletion;
its status remains REVOKED in provenance, and old report verification fails closed.
Saved reports remain readable. Revocation is not secure erasure of SSD sectors,
backups, filesystem snapshots or process memory. Protect and manage your backups.
A local HMAC is source authentication within your workspace, not a transferable
public signature or independent witness. Anyone controlling your OS user can
alter your workspace. Ancestor groups must be trusted; world-writable ancestors
are rejected, even sticky `/tmp`. Workspace files reject hardlinks and symlinks.

## Persistence, schemas, and privacy

`customer.py` is reusable independently of HTTP. It writes owner-only files under
an exclusively locked pinned workspace descriptor, with umask 077, 0700 directories,
0600 files and atomic JSON replacement. Secrets are in separate `key-<random-id>`
files only, never in public workspace JSON, pages, reports, exports or application
logs. No key-reading HTTP endpoint exists. No uploaded code is executed. Each run
uses the release's existing validation/reconstruction or evidence-state assessor.
Reports are deterministic for exact input, key and ruleset; their IDs hash their
canonical content. They retain an exact original-byte digest and analyzed-document
digest. The attestation changes only the reviewed copy, never the uploaded file.

Versioned customer workspace, report and export contracts use `*.v1` schema tags;
JSON Schemas are in `schemas/customer-*.schema.json`. Evidence-state input/output
remain unchanged. Detailed reports and signed documents are stored privately;
legacy raw input is temporary and removed after analysis. Evidence-state original
bytes are digested, with the canonical analyzed document retained. No delete-all
UI or encryption at rest is provided; remove a stopped workspace using your OS
and manage backups deliberately. Use disk encryption as appropriate.

The loopback server checks the exact Host including random port, mutation Origin,
HttpOnly SameSite session cookie and unpredictable CSRF header. It refuses nonlocal
binding and service-worker requests, sends no CORS grants and uses a restrictive
CSP with no inline scripts. Labels and evidence render as text. Browser requests
are only user-triggered local actions and initial local asset/state loading.
Session shutdown is explicit. A local process denial of service is outside scope.
A single-threaded server and five-second socket timeouts bound concurrency; JSON
transport wrappers allow escaping overhead but enforce separate decoded byte caps.

## Product and commercial boundary

Delivered: local onboarding, source enrollment, rotation/revocation, validation,
replay/assurance, source-bound customer attestation, diagnostics, result review,
historical verification and consented summary export. Separate workspace roots
provide local separation; this is **not hosted multi-tenant security**.

Not delivered: hosted accounts/sign-in, hosted customer isolation, business backend,
payments, ticket submission, remote connectors, vendor-managed operations or an
independent verifier/provenance integration. Independent assurance needs a separate
verifier and operational process. Hosted SaaS would require authentication,
authorization, retention/recovery design, tenant isolation and security assessment.
Future pricing may combine Apache-2.0 core with separately distributed paid
connectors, dashboard packaging or assurance services. Everything included here,
including this dashboard, remains Apache-2.0; prior license grants are unchanged.
See LICENSE and NOTICE. Optional third-party projects retain their own attribution.
No Stripe, GitHub Actions, third-party model or telemetry integration is added.

## Reproducible QA and synthetic demo

From the checkout, choose a fresh workspace **inside a trusted parent**:

```sh
PYTHONPATH=src python3 tools/customer_demo.py --workspace "$PWD/demo-customer-workspace"
PYTHONPATH=src:adapters/ddc/src python3 -m pytest -q -ra
python3 tools/release_smoke.py
git diff --check
```

The demo asserts supplied-vs-attested absence, report reproduction, rotation,
optional historical verification, diagnostics and consented redacted export.
All demo/test keys are generated synthetic keys. Do not use its records as customer
evidence. The HTTP acceptance tests start an actual random-port loopback server,
exercise authenticated routes, hostile inputs and click-equivalent requests, then
shut it down. They explicitly skip if the execution environment prohibits socket
creation; a skip leaves HTTP acceptance unverified, rather than proving it passed.
No real browser automation or independent security assessment is claimed.
