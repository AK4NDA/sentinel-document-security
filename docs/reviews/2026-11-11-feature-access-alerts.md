# Review, feature/access-alerts, 2026-11-11

**Reviewed by**: review subagent (fresh model; author on the implementing model)
**Scope**: 18 files, branch vs merge-base 814841a (origin/main)
**Verdict**: Approve with nits

## Summary

Spec 0010 adds an `alerts` table fed by a classifier hooked inside `audit.append`, plus `GET /v1/alerts` and `POST /v1/alerts/{id}/acknowledge` for admin/auditor. The implementation is faithful to the spec: the hook placement covers every append path (business transactions, `record_denial`, `append_with_retry`, fork retries), alert + `alert.raise` + trigger commit atomically per AC-11, and the acknowledge path uses a conditional UPDATE plus audited denials for 403/404/409. Test coverage is strong (19 new tests, every AC exercised). No blockers or majors; the findings below are minor noise/spec-edge concerns and small coverage gaps.

## Minor

### 🟡 Validation rejections on document surfaces raise `denied_access` alerts, `app/services/alerts.py:32` + `app/services/documents.py:86-94`

**Problem**: `_DENIED_PREFIXES` matches every `document.*`/`user.*`/`session.*` action with `outcome="denied"`. But `_audit_reject` records `document.upload`/`document.edit` denials for `too_large` and `unsupported_media_type` — input validation failures, not access-control denials. Each rejected upload now creates an alert row, an `alert.raise` audit entry, and consumes one slot of the actor's hourly `denied_access` cap.

**Why it matters**: A `user` role officer repeatedly uploading oversized or wrong-MIME files can exhaust their 20/hour `denied_access` cap, after which genuine probing denials in the same window produce no alert (AC-6 cap is per type). The feed also fills with non-security noise. The spec's trigger table literally says "denied outcome on any policy surface", so this is arguably spec-sanctioned — but the classifier cannot distinguish policy denials from validation rejections because both share `outcome="denied"`.

**Suggested fix**: Either exclude the validation-reject actions/details in the classifier (e.g., skip when `details.reason` is `too_large`/`unsupported_media_type`), or record validation rejects under a distinct action name. At minimum, confirm this is intended and note it in the spec.

### 🟡 Spec-listed coverage gaps: fork-retry rebuild and concurrent acknowledge, `tests/test_alerts.py`

**Problem**: The spec build plan (step 8) and design section call out testing the `AuditChainFork` retry path (alert insert + `alert.raise` rebuilt with primitives) and the concurrent-acknowledge race. The suite covers sequential acknowledge → 409 and plain rollback (AC-11), but there is no test that forces a chain fork mid-transaction to prove the alert rebuilds correctly on retry, and no concurrency test for two simultaneous acknowledges.

**Why it matters**: The fork path is the subtlest part of this change — `maybe_raise` runs inside `append`, so a fork on the nested `alert.raise` entry must roll back and rebuild the whole unit. A regression here would silently drop or duplicate alerts. The conditional-UPDATE guard for concurrent acknowledges is also only verified sequentially.

**Suggested fix**: Add a test that injects/forces `AuditChainFork` (e.g., by pre-claiming `prev_hash` or mocking `_tail_hash`) and asserts exactly one alert + one `alert.raise` survive the retry; optionally an `asyncio.gather` test with two sessions acknowledging the same alert asserting one 200 and one 409.

## Nits

- ⚪ `app/services/alerts.py:228-243` — `acknowledge` checks `self_acknowledge` before `already_acknowledged`, so the original actor re-acking an alert someone else already closed gets 403 rather than 409. Both are audited denials and the spec does not fix precedence; fine as-is, just noting the ordering is a choice.
- ⚪ `app/services/alerts.py:142-153` — `_summary` copies the entire `details` dict into `summary["details"]` when no `reason` key exists. Correct today (details are small and secret-free), but it is a blanket copy; if a future audited action puts bulky data in `details`, summaries grow unbounded. A whitelist of "key details" would be tighter per AC-10's wording.
- ⚪ `app/services/alerts.py:166-176` — `list_alerts` service signature types `state`/`alert_type` as bare `str`; the router's `Literal` params enforce validity, so this is only a typing-precision nit.

## Strengths

- Hook placement inside `audit.append` is the right call: every append path (`transact`, `record_denial`, `append_with_retry`, role-gate denials) is covered centrally with zero per-route wiring, and the `alert.*` prefix short-circuit makes recursion impossible by construction.
- Transactional discipline is exactly per AC-11: alert row, `alert.raise` entry, and trigger entry share one commit/rollback, verified by `test_alert_rolls_back_with_business_transaction`.
- Acknowledge is race-safe (conditional `UPDATE ... WHERE state='open'` + rowcount → 409) and every outcome — allow, self-deny, not-found, already-acked — is audited in the same transaction.
- Test suite is genuinely thorough: all four alert types, share-granted TS reads, per-actor and per-type cap dimensions, filter/pagination/422 validation, role and self guards, MFA gate coverage, and classifier negative space.

## Test coverage

`tests/test_alerts.py` (19 tests) covers every acceptance criterion including cap boundaries per actor and per type, recursion guard, rollback atomicity, and the clean-verify negative. Gaps: no forced `AuditChainFork` retry test proving alert rebuild (spec step 8), no true-concurrency acknowledge test, and no test for the `record_denial` path specifically raising an alert (denials via `require_role`/`_deny` are covered indirectly). Adequate for merge; the two spec-listed scenarios above are the ones worth adding.
