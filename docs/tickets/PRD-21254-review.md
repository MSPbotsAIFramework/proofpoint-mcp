# PRD-21254 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21254 @ 167db2c (base main @ c7f8548)

Verdict: approved

### Verification performed

- `uv sync && uv run pytest -q` on commit `167db2c`: `378 passed, 4 skipped` — matches the
  Self-test section of `docs/tickets/PRD-21254.md` exactly.
- `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .`: no hits.
- README `## MSPbots Connector` section (lines 17-88, untouched by this ticket's diff per
  `git diff c7f8548...HEAD -- README.md`) diffed against
  `vendor-mcp-development/reference/readme-connector-section.md`: only a pre-existing one-line
  trailing-blank-line gap, confirmed outside this ticket's changed hunks — matches the Self-test's
  claim.
- `src/proofpoint_mcp/tools/_common.py`: `locate`/`resume_fields`/`READ_ONLY`/`WRITES`/
  `DESTRUCTIVE` pre-date this diff (reused, not reinvented) — matches the Reuse & cleanup claim.
- `ProofpointCredentials.__repr__` (api_client.py) does not expose `pps_username`/`pps_password`;
  the shared `_send()` logging path (reused by `.pps()`) only logs method/path/status/ms/attempt,
  no headers or bodies.
- `.ac.json` test matrix cross-checked against the product design's AC1-AC11 and the diff: every
  AC has a corresponding TC, every `pass` cites a test that exists in the diff, TC-PPQ-005/007 are
  `blocked` with a stated reason (no PPS test tenant) per the MCP track's "missing test account is
  not a blocker" rule, not silently marked pass.

### Findings

No must-fix findings.

1. [suggestion] `src/proofpoint_mcp/server.py:222-242` (`normalize_pps_base_url`) — the PPS base
   URL has no domain-suffix allowlist, unlike the TAP cluster URL check in the same file. This is
   already flagged by the tech design (Non-functional / Host validation trade-off) with a stated
   reasoning (PPS hosts are tenant-specific/on-prem, credential and host come from the same
   tenant, trust boundary unchanged) — not re-litigated here as a blocker, but noting it for
   anyone reading the diff without the design doc open.
2. [suggestion] `src/proofpoint_mcp/tools/quarantine.py:471-491` (`_run`) duplicates a small
   amount of precondition-checking logic that is structurally similar to what `run_tool` does for
   the TAP path (client None / header_error / not-configured). The tech design explains why this
   can't simply reuse `run_tool` as-is (PPS has its own, independent not-configured/header-error
   pair that must not affect other tools) — acceptable as implemented, flagging only as a
   readability note for a future contributor who has to maintain two similar-but-not-identical
   precondition blocks.

### Conclusion

Diff matches the technical design's change list file-for-file. Tool contract (names, required
params) for the 4 quarantine tools is unchanged (AC10, verified by `test_tools.py::test_all_tools_
listed` / `test_required_params` passing). Multi-tenant isolation for the new PPS credential set
follows the same per-request, never-shared pattern already used for TAP/Reports (AC8, verified by
`test_list_isolates_pps_credentials_between_requests`). No new dependency, no DB/migration, no
UI. Approved for merge.

Status: frozen @ 167db2c
