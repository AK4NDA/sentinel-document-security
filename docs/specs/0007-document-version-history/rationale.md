# 0007 · Document version history: rationale

Decision record for [index.md](index.md). Read at design time; not needed to build.

## Context

Spec 0003 built the write side of versioning: `POST /v1/documents/{id}/versions` appends a new `document_versions` row with `version_number = max + 1`, classification equal to the editor's clearance, and moves `current_version_id`. Spec 0002 fixed the table shape and left restore semantics to this slice, recommending that restore insert a new version copying the old content rather than moving the pointer backwards, because the history is append only and the audit log is the chain of custody.

What is missing is the read side. An owner who edits a Secret document three times has no way to see what version 1 said, download it for comparison, or roll back after a bad edit. The scope's open question is how classification interacts with the write down rule across versions. Because each version's classification is pinned to its writer's clearance at write time, and clearances can change through administration, versions of one document can carry different classifications in both directions. A naive "check the current version's classification" rule would either hide legitimately readable old versions or leak the existence of versions classified above the caller.

Forces: Bell LaPadula deny by default applies to every version, not just the current one; the audit log must record every version event in the same transaction as the mutation; blob storage is content addressed so a restored version can reference the same encrypted blob without copying bytes; and concurrent edits already rely on the `(document_id, version_number)` unique constraint returning 409.

## Options considered

### Option 1: Append only history with per version access (chosen)

List, download, and restore all treat each `document_versions` row as an immutable record carrying its own classification. Restore appends a new version that reuses the source row's content fields and blob path. No schema changes.

**Pros**:
- Preserves the append only invariant the audit chain and spec 0002 designed for; every event, including restores, is itself a version
- Per version classification is honest: a version is protected by the clearance of whoever created it, matching how edits already work
- Content addressed blob storage means restore costs one row insert, no file copy and no re encryption

**Cons**:
- Classification on a restored version reflects the restorer's clearance, not the content's original sensitivity; a high cleared user can "upgrade" old content's label, which is consistent with edit but means classification tracks last touch, not content

### Option 2: Pointer restore with mutable current marker

Restore moves `current_version_id` back to the old version row without inserting anything.

**Pros**:
- Smallest possible change; no new version rows

**Cons**:
- Breaks append only history: the restore event leaves no version record, only an audit row pointing backwards
- The "current" version's `created_at` and authorship no longer describe when it became current, weakening chain of custody
- Rejected by the spec 0002 follow-up recommendation this slice was told to settle

### Option 3: Version content gated by current classification only

Old version downloads require clearance for the current version's classification, ignoring the target version's own classification.

**Pros**:
- One rule to explain; matches how `GET /content` already works

**Cons**:
- Wrong in both directions: hides old versions classified below a now higher current version, and would expose an old version classified above the caller if the current version were lower (possible after a clearance change)

### Option 4: Owner only history access

Only the document owner can list, download, or restore versions; other cleared readers see only the current version.

**Pros**:
- Maximum containment; history is the owner's business

**Cons**:
- Breaks the read model spec 0003 set: any sufficiently cleared user can already read document content, and hiding history from them is inconsistent without a stated reason
- The scope asks for reading and restoring with classification rules, not ownership walls

## Rationale

Append only wins because the audit log is the chain of custody: a pointer restore would let the current version's row claim an authorship and timestamp that no longer describe when it became current, and the restore itself would exist only as an audit line rather than as inspectable history. The spec 0002 follow up already recommended this shape, and the blob store being content addressed makes it nearly free. Per version access wins because classification is already stored per version and pinned to its writer's clearance; gating on the current version alone is wrong in both directions once clearances change, and owner only history access contradicts the read model spec 0003 shipped where any sufficiently cleared reader can read content. The two layered checks (document read plus per version classification) are slightly stricter than strictly necessary for old low versions under a higher current version, but they keep one simple mental model: you cannot touch any part of a document you cannot read, and you cannot touch any version above your clearance.

## References

**Project sources** (verifiable, in this repo):
- `AGENTS.md` deny by default, audit in the same transaction, and portable types rules
- `app/AGENTS.md` layered monolith conventions and audit actor snapshot rule
- spec 0002 data model (`document_versions` shape, append only invariant, restore recommendation)
- spec 0003 core classified document loop (version creation on edit, read and write rules, audit vocabulary)
- `app/services/documents.py`, `app/api/documents.py`, `app/models/document_version.py` as built

**Practices & standards**:
- Bell LaPadula no read up and no write down applied per object instance (each version is an object)
- Append only audit trails and chain of custody for classified content
- Separation of duties: restore is a mutation and stays owner only like edit and delete
