# PRD-21255 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21255 @ f98db4e (base main @ a906469)

Verdict: approved

### Scope

`git diff a906469...f98db4e` — 15 files changed (README.md, docs/tickets/PRD-21255.{md,ac.json},
src/proofpoint_mcp/{api_client.py,config.py,server.py}, src/proofpoint_mcp/tools/
{_common.py,essentials_admin.py (new),essentials_threat.py (new),navigation.py,tap.py,threats.py},
tests/{test_api_client.py,test_middleware.py,test_tools.py}). `a906469` is confirmed an ancestor
of `f98db4e` (`git merge-base --is-ancestor`), i.e. this branch already carries PRD-21254's
reviewed history forward via merge commit `1bcca45`; only the delta `a906469...f98db4e` (this
ticket's own commits `a802c60` and the resolution in `1bcca45`) is in scope here. `main` has not
moved since the dev leg's sync (`origin/main` is still `a906469`), so no re-sync was needed before
this review.

### Findings

No must-fix findings.

1. [suggestion] `src/proofpoint_mcp/tools/essentials_admin.py:67-76` (`_list_page`) — client-side
   pagination re-fetches the org's full domain/user list on every page call. This is a deliberate,
   well-documented tradeoff (module docstring, `docs/tickets/PRD-21255.md` "Decisions made by
   DEV01") given the vendor's own pagination contract is unconfirmed — acceptable for v1, but
   worth revisiting once a real Essentials account is available to test whether the vendor's
   `page`/`size` params can be trusted, per the ticket's own "Suggested follow-ups".
2. [suggestion] `src/proofpoint_mcp/server.py:200-236` (`_URL_HEADERS` / malformed-url handling)
   — only the first malformed base-url header is surfaced in `header_error`; if a caller sends two
   bad URLs at once only one is reported. Documented in a code comment as an accepted tradeoff
   ("rare for a caller to send two malformed base urls at once"); not worth the added complexity
   for v1.

### Verification performed

- `uv sync && uv run pytest -q` on `f98db4e` (this repo's own gate, no mypy/AGENTS.md declared):
  **441 passed, 4 skipped** — matches the Self-test section in `docs/tickets/PRD-21255.md`
  exactly (same 4 pre-existing skips, confirmed there against pristine `c7f8548`).
- `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .` — 0 hits, repo
  stays English-only.
- README `## MSPbots Connector` section (lines 21-92, up to the blank line before
  `## Authentication headers`) diffed byte-for-byte against
  `vendor-mcp-development/reference/readme-connector-section.md` — identical.
- `docs/tickets/PRD-21255.ac.json` — `ticket_store.py validate`: ledger OK, 12 cases.
- Credential/security review: Essentials Admin (`X-User`/`X-Password`) and Essentials Threat
  (Basic with Integration Key/Secret) credentials are read only from per-request headers
  (`server.py` middleware → `ProofpointCredentials` → `contextvars`), never cached across
  requests, never logged (`__repr__` redacts all new secret fields), never written to disk —
  matches the repo's existing TAP/Reports/PPS pattern. No new third-party dependency introduced.
- Backward compatibility (AC6): `CREDENTIAL_SETS`/`REQUIRED_HEADERS` change in `server.py:34-72`
  reviewed for any stale assumption elsewhere in the codebase that TAP's principal/secret are the
  only required pair — none found (`grep -rn REQUIRED_HEADERS` only resolves inside `server.py`
  itself). `test_an_incomplete_tap_pair_alone_is_still_401` and
  `test_a_complete_non_tap_set_alone_satisfies_the_gateway` cover both directions of this change.
- `_send()` call signature for the two new `ProofpointClient` methods
  (`api_client.py:253-275`, `essentials_admin`/`essentials_threat`) matches the existing
  `tap()`/`reports()`/`pps()` call shape exactly — no signature drift.
- Mid-dev-leg merge `1bcca45` (PRD-21254 sync): read the merge commit message in full. Both
  tickets' behavior preserved additively (PPS deliberately excluded from the new
  `CREDENTIAL_SETS` gate, per PRD-21254's own AC that PPS must never produce a hard 401) — no
  requirement from either ticket was silently dropped.
- Reuse: no duplicate HTTP client, retry/backoff, pagination or error-envelope logic introduced;
  `_register_siem_tool`, `locate`/`resume_fields`, `normalize_base_url` and `path_segment` were
  generalized/reused rather than copy-pasted, matching the tech design's "Reuse & cleanup"
  section. `path_segment` was moved from `tools/threats.py` to the shared `tools/_common.py`
  (verified the two original call sites plus a third inside `proofpoint_threat_list_families`
  still resolve correctly after the move — `uv run pytest` passing confirms this).
- No dead code, no TODO/FIXME/debug prints introduced (`git diff` grep for
  `print(|TODO|FIXME|XXX`: 0 hits in added lines).

### Conclusion

Design, implementation and tests are internally consistent and match the tech design's change
list exactly. The two suggestions above are non-blocking, already acknowledged in the ticket's
own "Decisions made by DEV01" / code comments, and do not affect correctness, security or
backward compatibility. Approved for merge into `main`, INT publish and the connector-wiki check.

Status: frozen @ f98db4e
