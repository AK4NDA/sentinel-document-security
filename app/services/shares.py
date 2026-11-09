"""Per user document sharing (spec 0009).

A share is a discretionary, read only, owner managed grant that lets one
named ``user`` role account read a document and all of its versions
regardless of classification. Every grant, revoke, and shared access is
audited; shares persist through admin actions on either side.
"""

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Document, DocumentShare, DocumentVersion, User, UserRole
from app.schemas.shares import SharedDocumentOut, ShareOut
from app.services import audit

GRANT_ACTION = "document.share_grant"
REVOKE_ACTION = "document.share_revoke"
LIST_ACTION = "document.shares_list"
MINE_ACTION = "document.list_shared"

_SHARE_LOADS = (
    selectinload(DocumentShare.grantee),
    selectinload(DocumentShare.granter),
    selectinload(DocumentShare.revoker),
)


async def _deny(
    db: AsyncSession,
    action: str,
    actor: User,
    reason: str,
    *,
    doc: Document | None = None,
    status_code: int = status.HTTP_403_FORBIDDEN,
    details: dict | None = None,
) -> None:
    await audit.record_denial(
        db,
        action=action,
        actor=actor,
        reason=reason,
        target_type="document" if doc else None,
        target_id=str(doc.id) if doc else None,
        details=details,
    )
    raise HTTPException(status_code, "forbidden" if status_code == 403 else "not found")


async def _owner_document(
    db: AsyncSession, actor: User, doc_id: uuid.UUID, action: str
) -> Document:
    """Fetch the document and require ownership; 404 does not reveal existence."""
    doc = (await db.execute(select(Document).where(Document.id == doc_id))).scalar_one_or_none()
    if doc is None or doc.owner_id != actor.id:
        await _deny(
            db,
            action,
            actor,
            "not_owner_or_missing",
            doc=doc,
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return doc


async def _active_share(
    session: AsyncSession, doc_id: uuid.UUID, user_id: uuid.UUID
) -> DocumentShare | None:
    result = await session.execute(
        select(DocumentShare).where(
            DocumentShare.document_id == doc_id,
            DocumentShare.user_id == user_id,
            DocumentShare.revoked_at.is_(None),
        )
    )
    return result.scalar_one_or_none()


async def _load_share(session: AsyncSession, share_id: uuid.UUID) -> DocumentShare:
    result = await session.execute(
        select(DocumentShare).options(*_SHARE_LOADS).where(DocumentShare.id == share_id)
    )
    return result.scalar_one()


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; normalize so responses match Postgres."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def to_share_out(share: DocumentShare) -> ShareOut:
    return ShareOut(
        id=share.id,
        user_id=share.user_id,
        username=share.grantee.username,
        access_level=share.access_level,
        granted_by=share.granter.username,
        created_at=_as_utc(share.created_at),
        revoked_at=_as_utc(share.revoked_at),
        revoked_by=share.revoker.username if share.revoker is not None else None,
    )


async def grant(
    db: AsyncSession, actor: User, doc_id: uuid.UUID, user_id: uuid.UUID
) -> tuple[DocumentShare, bool]:
    """Grant or reactivate a read share. Returns (share, created)."""
    doc = await _owner_document(db, actor, doc_id, GRANT_ACTION)
    grantee = await db.get(User, user_id)
    if grantee is None:
        await _deny(
            db,
            GRANT_ACTION,
            actor,
            "user_not_found",
            doc=doc,
            status_code=status.HTTP_404_NOT_FOUND,
            details={"grantee_id": str(user_id)},
        )
    if grantee.id == actor.id:
        await _deny(
            db,
            GRANT_ACTION,
            actor,
            "self_share",
            doc=doc,
            status_code=status.HTTP_409_CONFLICT,
            details={"grantee_id": str(user_id)},
        )
    if not grantee.is_active:
        await _deny(
            db,
            GRANT_ACTION,
            actor,
            "grantee_disabled",
            doc=doc,
            status_code=status.HTTP_409_CONFLICT,
            details={"grantee_id": str(user_id)},
        )
    if grantee.role != UserRole.USER:
        await _deny(
            db,
            GRANT_ACTION,
            actor,
            "grantee_role",
            doc=doc,
            status_code=status.HTTP_409_CONFLICT,
            details={"grantee_id": str(user_id)},
        )

    snapshot = audit.actor_kwargs(actor)
    actor_id = actor.id

    async def attempt(session: AsyncSession) -> tuple[DocumentShare, bool]:
        existing = (
            await session.execute(
                select(DocumentShare).where(
                    DocumentShare.document_id == doc_id,
                    DocumentShare.user_id == user_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None and existing.revoked_at is None:
            return existing, False
        if existing is None:
            share = DocumentShare(
                document_id=doc_id,
                user_id=user_id,
                granted_by=actor_id,
                access_level="read",
            )
            session.add(share)
            await session.flush()
            created = True
        else:
            share = existing
            share.granted_by = actor_id
            share.revoked_at = None
            share.revoked_by = None
            created = False
        await audit.append(
            session,
            action=GRANT_ACTION,
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            details={"share_id": str(share.id), "grantee_id": str(user_id)},
            **snapshot,
        )
        return share, created

    try:
        share, created = await audit.transact(db, attempt)
    except IntegrityError:
        await db.rollback()
        # Lost the insert race: the winner's committed row is the answer.
        # Dialect neutral: any integrity failure is confirmed by the re-read,
        # so a violation that is not the pair conflict still surfaces.
        winner = await _active_share(db, doc_id, user_id)
        if winner is None:
            raise
        return await _load_share(db, winner.id), False
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    return await _load_share(db, share.id), created


async def revoke(db: AsyncSession, actor: User, doc_id: uuid.UUID, user_id: uuid.UUID) -> None:
    await _owner_document(db, actor, doc_id, REVOKE_ACTION)
    snapshot = audit.actor_kwargs(actor)
    actor_id = actor.id

    async def attempt(session: AsyncSession) -> str:
        share = await _active_share(session, doc_id, user_id)
        if share is None:
            await audit.append(
                session,
                action=REVOKE_ACTION,
                outcome="denied",
                target_type="document",
                target_id=str(doc_id),
                details={"reason": "share_not_active", "grantee_id": str(user_id)},
                **snapshot,
            )
            return "share_not_active"
        share.revoked_at = datetime.now(UTC)
        share.revoked_by = actor_id
        await audit.append(
            session,
            action=REVOKE_ACTION,
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            details={"share_id": str(share.id), "grantee_id": str(user_id)},
            **snapshot,
        )
        return "ok"

    try:
        kind = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    if kind != "ok":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")


async def list_shares(
    db: AsyncSession, actor: User, doc_id: uuid.UUID, *, path: str
) -> list[DocumentShare]:
    await _owner_document(db, actor, doc_id, LIST_ACTION)
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> list[DocumentShare]:
        rows = list(
            (
                await session.execute(
                    select(DocumentShare)
                    .options(*_SHARE_LOADS)
                    .where(DocumentShare.document_id == doc_id)
                    .order_by(DocumentShare.created_at, DocumentShare.id)
                )
            )
            .scalars()
            .all()
        )
        await audit.append(
            session,
            action=LIST_ACTION,
            outcome="allowed",
            target_type="endpoint",
            target_id=path,
            **snapshot,
        )
        return rows

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None


async def list_mine(db: AsyncSession, actor: User, *, path: str) -> list[SharedDocumentOut]:
    """Active shares held by the caller, newest grant first (spec 0009 AC-6)."""
    actor_id = actor.id
    stmt = (
        select(Document, DocumentShare, User.username, DocumentVersion.classification)
        .join(DocumentShare, DocumentShare.document_id == Document.id)
        .join(DocumentVersion, DocumentVersion.id == Document.current_version_id)
        .join(User, User.id == Document.owner_id)
        .where(
            DocumentShare.user_id == actor_id,
            DocumentShare.revoked_at.is_(None),
        )
        .order_by(DocumentShare.created_at.desc(), Document.id)
    )
    rows = (await db.execute(stmt)).all()
    # Build response objects before transact: a chain fork rollback expires
    # ORM state, and the retry must not touch it.
    documents = [
        SharedDocumentOut(
            id=doc.id,
            title=doc.title,
            description=doc.description,
            classification=classification,
            owner=owner_username,
            shared_at=_as_utc(share.created_at),
        )
        for doc, share, owner_username, classification in rows
    ]
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> list[SharedDocumentOut]:
        await audit.append(
            session,
            action=MINE_ACTION,
            outcome="allowed",
            target_type="endpoint",
            target_id=path,
            **snapshot,
        )
        return documents

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
