# Review, feature/runnable-demo-packaging, 2026-11-12

**Reviewed by**: review subagent (fresh eyes; author model unknown)
**Scope**: 12 files, branch vs `main` (merge base c5f8910)
**Verdict**: Approve with nits

## Summary

The change adds a dev-only `seed-demo` CLI command that creates/repairs a fixed five-persona demo cast (admin, auditor, three officers across clearances) with pre-enrolled TOTP secrets, plus `scripts/walkthrough.py`, an httpx-driven live-API tour covering logins, uploads, deny paths, versions, search, sharing, alerts, and audit verification, backed by `app/demo_constants.py` as the single credential source and docs in `docs/demo/walkthrough.md`. Quality is high: every endpoint path, payload shape, and response key the script consumes was verified against the routers and schemas, the env and localhost guards match the spec's credential-hygiene rationale, audit entries stay inside the business transaction, and the new tests genuinely exercise login, repair, refusal, and chain verification (29 tests pass; ruff clean). Findings are edge-case robustness gaps in the repair path and walkthrough failure handling, none blocking.

## Minor

### 🟡 `wait_ready` failure escapes the labeled step runner as a traceback, `scripts/walkthrough.py:431`

**Problem**: `run()` calls `self.wait_ready()` before the `try/finally` that wraps the step loop. `wait_ready` raises `StepFailed` on timeout, which propagates uncaught through `main()` — the user gets a Python traceback instead of the `== step` / `FAIL:` format every other failure produces.
**Why it matters**: AC-8/AC-9 want a clean "expected vs actual" style failure; a traceback is uglier and inconsistent, and `verify.md` claims a "clear timeout message" which technically appears but buried in a stack trace. Exit code is still nonzero, so behavior is correct, just rough.
**Suggested fix**: Wrap `wait_ready()` in the same try/except (or move it inside the step loop's error handling) so a readiness timeout prints `FAIL: api not ready within 60s: ...` and returns 1 like any other step.

### 🟡 `_repair` leaves lockout and credential drift behind, `app/services/demo.py:33-70`

**Problem**: Repair tops up `role`, `clearance`, `is_active`, and TOTP state, but not `failed_login_attempts`/`locked_until`, `password_hash`, `email`, or `display_name`. Two consequences: (a) a demo account locked by 5 failed logins stays locked after `seed-demo` reports "repaired", so the very next walkthrough login fails; (b) if a username collides with a non-demo account, repair silently rewrites that account's role/clearance/TOTP while keeping its password — the documented credentials then don't work and an unrelated account was mutated.
**Why it matters**: The feature's promise is "safe to re-run, tops up drifted fields". Lockout is transient state a demo runner can plausibly create (fat-fingered manual login), and the username-collision case produces a confusing half-repaired account. Dev-only guard bounds the blast radius, so this is not a security issue.
**Suggested fix**: In `_repair`, also reset `failed_login_attempts = 0` and `locked_until = None` (cheap, matches "make the demo work again" intent), and either reset `password_hash`/`email`/`display_name` to the constants or skip repair with a warning when the existing row doesn't look like a demo account (e.g. email mismatch).

### 🟡 Seed audit appends have no chain-fork retry, `app/services/demo.py:82-112`

**Problem**: `seed_demo` calls `audit.append` directly inside one transaction. `append` raises `AuditChainFork` when the unique `prev_hash` constraint fires, and nothing retries — the documented demo flow runs `seed-demo` while the compose API is up and serving, so a concurrent audit write can lose the race and crash the command with an unhandled `AuditChainFork` traceback.
**Why it matters**: Rare, loud, and self-healing on rerun, but it hits exactly the documented usage (seed against a live stack). Other multi-append paths use `audit.transact`/`append_with_retry` for this reason.
**Suggested fix**: Either wrap the per-user work in `audit.transact`-style retry, or catch `AuditChainFork` in `_seed_demo` (cli.py) and print a "concurrent audit write, retry" message with exit 1 — matching the existing `IntegrityError` handling.

### 🟡 Alert-dependent step can fail on rapid repeat runs, `scripts/walkthrough.py:354-367`

**Problem**: `step_auditor_lists_and_acks_alert` requires a fresh open `denied_access` alert for `demo-officer-low` on every run, but `services/alerts.py` caps alerts per actor per type per rolling hour (`ALERT_HOURLY_CAP`, default 20). Each run generates ~2 such alerts for officer-low (denied read + denied read after revoke), so after roughly 10 runs within an hour the classifier silently stops creating alerts and the step fails with "open denied_access alert".
**Why it matters**: Docs promise repeatable demos ("safe to re-run", per-run unique titles). The failure is loud and the fix is "wait an hour or disable alerts", but it is undocumented.
**Suggested fix**: Either note the hourly cap in `docs/demo/walkthrough.md`'s repeat-runs section, or have the step fall back to acknowledging any open `denied_access` alert regardless of actor when the actor-filtered list is empty.

### 🟡 Most walkthrough step bodies are untested, `tests/test_walkthrough.py`

**Problem**: Tests cover fixtures, the remote guard, base-URL resolution, login failure modes, 429 mapping, and three step assertions (audit verify, search leak, alert absence). The bulk of the script — upload/version/share/delete step methods, `step_versions_list_download_restore`'s version-count logic, and the full `steps()` ordering — has no automated coverage; it is only exercised by the manual `/check verify` run against a live stack.
**Why it matters**: TESTS=configured; these are the script's core branching assertions (expected version counts, share-then-revoke transitions). A regression in e.g. the `expect=(200, 201)` share status or the `len(versions) == 3` post-restore check would only surface during a live demo.
**Suggested fix**: Extend the existing `FakeClient` pattern with a scripted happy-path handler that walks all steps — the infrastructure is already there, it just isn't used for the full tour.

## Nits

- ⚪ `scripts/walkthrough.py:379`, `steps()` is typed `list[tuple[str, object]]` which forces `# type: ignore[operator]` at the call site; `Callable[[], None]` removes the ignore.
- ⚪ `docs/scope/scope.md:225`, the feature row still reads "in-progress" while every subtask box is checked; presumably flips to done on merge, worth confirming.
- ⚪ `scripts/walkthrough.py:62-63`, `secret_token`/`top_secret_token` are dataclass fields though constant per process; class-level constants or `field(init=False)` would better express intent. Harmless as-is.

## Strengths

- Single source of truth for credentials: `app/demo_constants.py` is imported by both `cli.py` and `scripts/walkthrough.py`, and `test_demo_seed.py` asserts the docs-facing behavior (full MFA login per persona, drift repair including wrong TOTP secret, ENV refusal, audit entries with null actor and `via: "seed-demo"`, chain verify) rather than mocks.
- Guards are well-reasoned and tested: dev-only `ENV` check inside `seed_demo` (not just the CLI), and `_is_local` host parsing with `--allow-remote` override, parametrized over localhost/127.0.0.1/::1/remote cases.
- The walkthrough consumes only real API surface with per-persona cookie isolation, runtime-generated fixtures in a `TemporaryDirectory` cleaned in `finally`, per-run unique titles/tokens so repeat runs can't collide, bounded `/readyz` polling, and explicit expected-status tuples that make failures diagnosable.
- Spec adherence is unusually tight: every AC maps to code, `verify.md` records live proof, and the audit writes correctly stay inside the seed transaction with actor columns null per convention.

## Test coverage

29 new tests, all passing (`uv run pytest tests/test_demo_seed.py tests/test_walkthrough.py`), plus clean `ruff check`/`format`. Seed coverage is strong (create, idempotent exists, role/clearance/active/TOTP repair, wrong-secret repair, env refusal, audit + chain verify, all four CLI exit paths). Walkthrough coverage is partial: failure paths and a few step assertions are unit-tested via `FakeClient`, but the happy-path step sequence and most step bodies rely on the manual verify run — flagged above as a Minor given the configured test signal.
