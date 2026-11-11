# Rationale: Access alerts

## Context

The system already records every allowed and denied action in a hash chained audit log, and auditors can browse and verify that log. What is missing is a triage layer: the interesting events (denials, Top Secret reads, privilege changes, tamper evidence) are buried in a firehose of routine entries. Scope feature 11 asks for alert records that admins and auditors can review, with the channel decision (in app records versus email) left open; the scope recommends in app records to keep the demo self contained.

The project's audit rules constrain the design heavily: every audited behavior shares one action name across allow and deny, audit appends happen inside the business transaction, and the chain's `prev_hash` uniqueness already serializes appends with retry. Any alert mechanism that wrote outside that transaction would break the "audit in the same transaction" invariant the whole security model rests on.

## Options considered

### Option 1: Derived alert view over the audit log

No new table; alerts are computed by filtering `audit_log` rows on demand (denied outcomes, Top Secret reads, admin mutations, failed verifies).

**Pros**:

- Zero new storage, zero new write path, nothing can drift from the audit log.

**Cons**:

- No acknowledge state: triage requires an external notebook, and "which denials were reviewed" is unanswerable.
- Recomputing interestingness on every list call couples alert semantics to audit query performance and makes per actor rate caps impossible to enforce at write time.
- Failed chain verification cannot be derived at all, since a tampered chain is exactly the state where derived views lie.

### Option 2: In app alert records fed from the audit pipeline (chosen)

A new `alerts` table holds one row per qualifying event, written inside the same transaction as the triggering audit append, with a compact summary and a pointer (`audit_seq`) back to the audit entry. Admins and auditors list and acknowledge through a small REST surface.

**Pros**:

- Alerts inherit the audit transaction and tamper evidence for free; an alert cannot exist without its chained audit entry.
- Acknowledge state gives reviewers a real triage workflow inside the product.
- The hourly per actor per type cap bounds volume during brute force or probing while the audit log keeps the full record.

**Cons**:

- New write path inside business transactions: extra inserts and a cap count query on every qualifying action.
- A trigger classifier must be maintained as new audited actions appear; a missed action produces no alert with no error.
- `summary` is a small duplicated snapshot that can drift from the audit entry in shape, though never in fact since both commit together.

### Option 3: Email or webhook alert channel

Alerts are generated in app and delivered by email or webhook to a distribution list.

**Pros**:

- Alerts reach reviewers who are not logged in, which matters for a real deployment.

**Cons**:

- Requires SMTP or webhook infrastructure, credentials, and delivery failure handling the demo does not need.
- Delivery is inherently outside the audit transaction, so the "alert exists iff audit entry exists" guarantee is lost unless a local record is kept anyway, at which point in app records already exist and email becomes a thin notifier on top.

## Rationale

Option 2 was chosen because it is the only option that preserves the project's core invariant (audit and its consequences commit atomically) while still giving reviewers stateful triage. Option 1 cannot represent acknowledge or tamper alerts; Option 3 solves notification, not record keeping, and the scope explicitly recommends in app records for this pass. Email delivery stays a deferred scope item and can later be layered on top of the alert table as a notifier without changing this decision.

Two refinements came out of design review. First, the classifier hooks inside `audit.append` rather than at each call site: `record_denial` rolls back before appending and `append_with_retry` owns its own session, so only a central hook covers every append path correctly, and fork retries rebuild the alert with the same primitives as the audit entry. Second, the hourly cap is documented as best effort rather than a hard bound, because two concurrent transactions can both pass the count; the audit log retains every event regardless, so the cap is a readability control, not a correctness guarantee.

The self acknowledge block and the 20 per hour cap are deliberate friction: the first keeps a second pair of eyes on events like privilege changes, the second keeps a brute force run from drowning the feed while the audit log retains every attempt.
