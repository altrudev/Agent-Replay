# Vendored APS oracle-safety-check fixtures

These files are exact test inputs copied from the public Agent Authority Conformance suite for deterministic interoperability testing.

Source repository: `Agent-Authority-Conformance/aps-conformance-suite`  
Pinned revision: `6e8b05b202d727ef18e84e100fc31db11f36529f`  
Source path: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1/`

Agent Replay does not treat the presence of these vendored files as cryptographic provenance for arbitrary APS input. Their repository/revision/path are known because this test directory is pinned deliberately; normal CLI input provenance remains unknown unless the caller supplies it.

The 13 cases are exercised directly by `tests/test_aps_authority.py`. Any future update to the upstream fixture family must use a new pinned revision and be reviewed as an evidence-contract change.
