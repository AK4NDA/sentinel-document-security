# 0009 · Per user document sharing

**Status**: In Progress
**Date**: 2026-11-09

## Context

> ⚠️ Premise note: this feature deliberately departs from strict Bell LaPadula. The no read up rule says a subject may never read an object classified above their clearance; a share overrides exactly that for one named user. That is the point of the feature (the scope asks for sharing with a colleague who could not otherwise read the document), but it means clearance is no longer the whole confidentiality story: the audit trail becomes the only record of who exposed what to whom. The spec compensates with mandatory auditing of grants, revokes, and every shared access, and by keeping shares read only so the write side of the model is untouched.

Spec 0002 reserved the `document_shares` table for this slice: one row per `(document_id, user_id)` pair with `granted_by`, `access_level`, `created_at`, `revoked_at`, and `revoked_by`, unique on the pair, supporting revoke and regrant. Spec 0003 built the policy engine (`services/policy.py`) as deny by default: officers (`user` role) read when `clearance >= classification`, and only owners edit or delete. Spec 0007 added version history where each version carries its own classification and listing filters per version by clearance. Spec 0008 kept search purely clearance based so results never reveal documents above the caller's clearance.

Today there is no way for an owner to expose a document to a specific person. The gaps this spec must close: the read path in `services/documents.py` has no share awareness, version listing filters by clearance per version (which would hide shared history), `GET /v1/documents` lists only owned documents, only admins can list users so owners cannot discover grantees, and no share management or discovery endpoints exist. If undecided, `/develop` would invent grant semantics, audit shapes, and edge case handling mid build.

## Options considered

### Option 1: Discretionary per user read grant (share overrides clearance)

A share row makes one named user able to read one document and all its versions regardless of clearance, managed only by the owner, revoked by clearing `revoked_at`. This matches the scope's requirement that a colleague who could not otherwise read the document gains access, and it uses the table spec 0002 already built.

**Pros**:
- Delivers the feature's actual purpose: named access beyond clearance
- Flat grant graph, owner controlled, trivially auditable
- No schema change; the existing unique pair already supports revoke and regrant

**Cons**:
- Breaks strict Bell LaPadula confidentiality for the grantee; an admin lowering a user's clearance does not cut shared access
- Every shared read must be audited or the discretionary trail has gaps

### Option 2: Clearance bounded share

A share only extends access to users whose clearance already meets the document's classification; it helps with ownership or role denials but never reads above clearance.

**Pros**:
- Preserves Bell LaPadula exactly; no policy departure
- Simpler auditor story: clearance remains the only confidentiality input

**Cons**:
- Fails the scope's core case: cannot share with a colleague cleared below the document
- Adds a rule that is hard to explain ("share helps only sometimes")

### Option 3: Group or role based sharing

Share with a group, role, or clearance tier instead of named users.

**Pros**:
- Fewer grants to manage at scale
- Matches some real world sharing models

**Cons**:
- No group entity exists in the data model; building one is a second feature
- Weaker audit granularity and harder revocation semantics
- Premature for a single owner workflow

## Rationale

The scope row for this feature is explicit that the grantee is someone who "could not otherwise read" the document, which only Option 1 satisfies; Option 2 was the runner up and was rejected because it cannot deliver the stated job. Option 3 was rejected because no group concept exists and per user rows are what spec 0002 already committed to. The clearance override is the dangerous part of this decision, so it is paid for with three compensating controls decided during the interview: shares are read only so the write side of BLP is untouched, grant rejects every ineligible target so an active share always implies an eligible grantee, and every shared access carries `via_share` in the audit details so discretionary reads are distinguishable from clearance reads. Shares persisting through admin actions was chosen over auto revoke because silent revocation would hide owner intent and complicate the audit story; the existing account gates already neutralize disabled or demoted grantees.
