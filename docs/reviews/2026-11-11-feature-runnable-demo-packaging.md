# Review, feature/runnable-demo-packaging, 2026-11-11

**Reviewed by**: SWE-2 Flash (author on SWE-2 Flash; degraded same model review, the cross model guarantee was unavailable in this environment)
**Scope**: 12 files, branch vs main (merge base c5f8910)
**Verdict**: Approve with nits

## Summary

The change adds the demo packaging slice: a shared cast module, a `seed-demo` CLI with dev only guard and idempotent repair, a guided httpx walkthrough covering every feature surface, docs, and tests. The code is careful where it matters: one transaction for the whole cast, audit entries inside that transaction, per persona clients, and honest guards on credentials. No blockers or majors; the findings are small robustness and polish items.

## Minor

### 🟡 Ready poll failure skips fixture and client cleanup, `scripts/walkthrough.py:431`

**Problem**: `run()` calls `self.wait_ready()` before the `try/finally` that closes clients and cleans the temp directory. A `StepFailed` from the ready poll propagates with `fixtures.cleanup()` never called.
**Why it matters**: the temp upload directory leaks on the most common failure mode (API not up). `TemporaryDirectory` has a finalizer so it is eventually reclaimed, but the cleanup contract the spec states ("removes the temp files when finished") is not honored on this path.
**Suggested fix**: move `wait_ready()` inside the `try`, or wrap the whole body including the poll.

### 🟡 Login never asserts the session belongs to the persona, `scripts/walkthrough.py:157-159`

**Problem**: after `mfa/verify`, `login()` fetches `/v1/auth/me` and stores the profile but never checks `username == demo.username`.
**Why it matters**: AC-2 requires each account to read its own profile. If session cookies ever bled between personas (the exact failure the per persona client design guards against), the tour would not notice.
**Suggested fix**: assert `me.json()["username"] == demo.username` in `login()`.

### 🟡 Alert hourly cap can break repeat demos, `app/services/alerts.py:124` interacting with `scripts/walkthrough.py`

**Problem**: each tour run produces roughly two `denied_access` alerts for `demo-officer-low` (pre share denied read plus post revoke denied read). `ALERT_HOURLY_CAP` defaults to 20 per actor per type per rolling hour, so about ten runs in an hour exhaust the budget and the alert step fails with "open denied_access alert" missing.
**Why it matters**: repeat demos are an explicit use case; the failure mode is confusing because it looks like a product bug.
**Suggested fix**: document the cap alongside the rate limit note in `docs/demo/walkthrough.md`, or have the tour acknowledge alerts as it goes so the open set stays small (the cap counts raised alerts, not open ones, so acknowledging does not help; spacing runs or raising the cap for demo envs is the real lever).

## Nits

- ⚪ `scripts/walkthrough.py:177`, `step_officer_denied_by_design` tests admin and auditor denial, not officer denial; rename to something like `step_admin_auditor_cannot_reach_documents`.
- ⚪ `scripts/walkthrough.py:90`, `self.profiles` is populated in `login()` and never read; drop it or use it.
- ⚪ `scripts/walkthrough.py:385`, `steps()` types the callables as `object` and `run()` needs `# type: ignore[operator]`; annotate as `Callable[[], None]` and drop the ignore.
- ⚪ `scripts/walkthrough.py:115`, `StepFailed` messages embed `resp.text[:300]`; a future endpoint that echoes request data could leak a pending token into logs. Low risk today.
- ⚪ `scripts/walkthrough.py:428`, a ready poll timeout surfaces as an uncaught traceback rather than the labeled step format; already noted in verify, polish only.

## Strengths

- Seed is genuinely atomic: all five users plus their audit entries commit or roll back together, and repair compares the sealed TOTP secret by decrypting it rather than trusting ciphertext equality.
- The walkthrough only uses public endpoints and captures every id from live responses, so it cannot drift into testing a parallel reality; per run unique titles make repeat runs safe by construction.
- Guard rails are layered and tested: dev only seed, localhost only tour, explicit `--allow-remote`, and a 429 path that names the actual fix.

## Test coverage

`TEST_SIGNAL = configured`. `tests/test_demo_seed.py` covers creation, login, idempotency, role/clearance/MFA drift repair including wrong secret, ENV refusal, audit entries and chain verify, plus CLI exit codes. `tests/test_walkthrough.py` covers the remote guard, env fallback, fixture generation, 429 hint, fail fast reporting, and key step assertions via a fake transport. The only uncovered logic is the middle of the tour's happy path, which `/check verify` exercises live against compose; a full mock would duplicate the server.
