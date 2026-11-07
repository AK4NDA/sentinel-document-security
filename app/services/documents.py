"""Document upload, read, edit, delete behind the BLP policy (spec 0003)."""

import hashlib
import re
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Document, DocumentVersion, User
from app.schemas.documents import DocumentMeta
from app.services import audit, blob_store

MAX_UPLOAD_BYTES = 25 * 1024 * 1024

ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

_MIME_EXTENSIONS = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "text/csv": ".csv",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}


def _normalize_mime(content_type: str | None) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def check_upload(content: bytes, mime_type: str | None) -> str:
    """Size first (413), then mime allowlist (415). Returns normalized mime."""
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file too large")
    normalized = _normalize_mime(mime_type)
    if normalized not in ALLOWED_MIME_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "unsupported media type")
    return normalized


_UPLOAD_CHUNK = 1024 * 1024


async def read_capped(file: UploadFile) -> bytes:
    """Read an upload in chunks, rejecting past the cap before buffering it."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_UPLOAD_CHUNK):
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _audit_reject(
    db: AsyncSession,
    action: str,
    actor: User,
    file: UploadFile,
    status_code: int,
) -> None:
    reason = "too_large" if status_code == 413 else "unsupported_media_type"
    await audit.record_denial(
        db,
        action=action,
        actor=actor,
        reason=reason,
        target_type="document",
        details={"filename": file.filename or "upload"},
    )


def to_meta(doc: Document) -> DocumentMeta:
    version = doc.current_version
    if version is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "document has no version")
    return DocumentMeta(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        owner_id=doc.owner_id,
        classification=version.classification,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
    )


async def _fetch_document(session: AsyncSession, doc_id: uuid.UUID) -> Document | None:
    result = await session.execute(
        select(Document)
        .options(selectinload(Document.current_version))
        .where(Document.id == doc_id)
    )
    return result.scalar_one_or_none()


async def _deny(
    db: AsyncSession,
    action: str,
    actor: User,
    reason: str,
    doc: Document | None = None,
    status_code: int = status.HTTP_403_FORBIDDEN,
) -> None:
    await audit.record_denial(
        db,
        action=action,
        actor=actor,
        reason=reason,
        target_type="document" if doc else None,
        target_id=str(doc.id) if doc else None,
    )
    raise HTTPException(status_code, "forbidden" if status_code == 403 else "not found")


async def _readable_document(
    db: AsyncSession, actor: User, doc_id: uuid.UUID, action: str
) -> Document:
    """Fetch + BLP read check; audits 404/403 denials. Caller must be officer."""
    doc = await _fetch_document(db, doc_id)
    if doc is None:
        await _deny(db, action, actor, "not_found", status_code=status.HTTP_404_NOT_FOUND)
    version = doc.current_version
    if version is None or actor.clearance < version.classification:
        await _deny(db, action, actor, "clearance", doc=doc)
    return doc


async def upload(
    db: AsyncSession,
    actor: User,
    *,
    file: UploadFile,
    title: str,
    description: str | None,
) -> Document:
    try:
        content = await read_capped(file)
        mime = check_upload(content, file.content_type)
    except HTTPException as exc:
        await _audit_reject(db, "document.upload", actor, file, exc.status_code)
        raise
    filename = file.filename or "upload"
    blob_path, digest = await blob_store.store(content)
    snapshot = audit.actor_kwargs(actor)
    owner_id = actor.id
    clearance = actor.clearance

    async def attempt(session: AsyncSession) -> Document:
        doc = Document(title=title, description=description, owner_id=owner_id)
        session.add(doc)
        await session.flush()
        version = DocumentVersion(
            document_id=doc.id,
            version_number=1,
            classification=clearance,
            content_sha256=digest,
            blob_path=blob_path,
            size_bytes=len(content),
            mime_type=mime,
            key_id="master",
            key_version="1",
            created_by=owner_id,
        )
        session.add(version)
        await session.flush()
        doc.current_version_id = version.id
        await session.flush()
        await audit.append(
            session,
            action="document.upload",
            outcome="allowed",
            target_type="document",
            target_id=str(doc.id),
            details={"filename": filename, "size_bytes": len(content)},
            **snapshot,
        )
        return doc

    try:
        doc = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    await db.refresh(doc, attribute_names=["current_version"])
    return doc


async def list_own(db: AsyncSession, actor: User) -> list[Document]:
    snapshot = audit.actor_kwargs(actor)
    owner_id = actor.id

    async def attempt(session: AsyncSession):
        rows = (
            (
                await session.execute(
                    select(Document)
                    .options(selectinload(Document.current_version))
                    .where(Document.owner_id == owner_id)
                    .order_by(Document.created_at.desc(), Document.id)
                )
            )
            .scalars()
            .all()
        )
        await audit.append(
            session,
            action="document.list",
            outcome="allowed",
            target_type="document",
            **snapshot,
        )
        return list(rows)

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None


async def read_meta(db: AsyncSession, actor: User, doc_id: uuid.UUID) -> DocumentMeta:
    doc = await _readable_document(db, actor, doc_id, "document.read")
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> Document:
        fresh = await _fetch_document(session, doc_id)
        await audit.append(
            session,
            action="document.read",
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            **snapshot,
        )
        return fresh

    try:
        doc = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    return to_meta(doc)


def _download_filename(title: str, mime_type: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", title).strip("._")[:100]
    if not safe:
        safe = "document"
    return safe + _MIME_EXTENSIONS.get(mime_type, "")


async def read_content(db: AsyncSession, actor: User, doc_id: uuid.UUID) -> tuple[bytes, str, str]:
    """Returns (plaintext, filename, mime_type)."""
    doc = await _readable_document(db, actor, doc_id, "document.download")
    version = doc.current_version
    snapshot = audit.actor_kwargs(actor)

    plaintext = await blob_store.load(version.blob_path)
    if hashlib.sha256(plaintext).hexdigest() != version.content_sha256:
        await audit.record_denial(
            db,
            action="document.download",
            actor=actor,
            reason="integrity_mismatch",
            target_type="document",
            target_id=str(doc.id),
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "integrity check failed")

    async def attempt(session: AsyncSession):
        await audit.append(
            session,
            action="document.download",
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            **snapshot,
        )

    filename = _download_filename(doc.title, version.mime_type)
    mime = version.mime_type
    try:
        await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    return plaintext, filename, mime


async def edit(
    db: AsyncSession,
    actor: User,
    doc_id: uuid.UUID,
    *,
    file: UploadFile,
    title: str | None,
    description: str | None,
) -> Document:
    doc = await _fetch_document(db, doc_id)
    if doc is None or doc.owner_id != actor.id:
        await _deny(
            db,
            "document.edit",
            actor,
            "not_owner_or_missing",
            doc=doc,
            status_code=status.HTTP_404_NOT_FOUND,
        )
    version = doc.current_version
    if version is None or actor.clearance < version.classification:
        await _deny(db, "document.edit", actor, "clearance", doc=doc)
    try:
        content = await read_capped(file)
        mime = check_upload(content, file.content_type)
    except HTTPException as exc:
        await _audit_reject(db, "document.edit", actor, file, exc.status_code)
        raise
    filename = file.filename or "upload"
    blob_path, digest = await blob_store.store(content)
    snapshot = audit.actor_kwargs(actor)
    owner_id = actor.id
    clearance = actor.clearance

    async def attempt(session: AsyncSession) -> Document:
        doc = await _fetch_document(session, doc_id)
        max_version = (
            await session.execute(
                select(func.max(DocumentVersion.version_number)).where(
                    DocumentVersion.document_id == doc_id
                )
            )
        ).scalar_one()
        new_version = DocumentVersion(
            document_id=doc_id,
            version_number=(max_version or 0) + 1,
            classification=clearance,
            content_sha256=digest,
            blob_path=blob_path,
            size_bytes=len(content),
            mime_type=mime,
            key_id="master",
            key_version="1",
            created_by=owner_id,
        )
        session.add(new_version)
        await session.flush()
        doc.current_version_id = new_version.id
        if title is not None:
            doc.title = title
        if description is not None:
            doc.description = description
        doc.updated_at = datetime.now(UTC)
        await session.flush()
        await audit.append(
            session,
            action="document.edit",
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            details={
                "filename": filename,
                "size_bytes": len(content),
                "version_number": new_version.version_number,
            },
            **snapshot,
        )
        return doc

    try:
        doc = await audit.transact(db, attempt)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "version conflict") from exc
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    await db.refresh(doc, attribute_names=["current_version"])
    return doc


async def delete(db: AsyncSession, actor: User, doc_id: uuid.UUID) -> None:
    doc = await _fetch_document(db, doc_id)
    if doc is None or doc.owner_id != actor.id:
        await _deny(
            db,
            "document.delete",
            actor,
            "not_owner_or_missing",
            doc=doc,
            status_code=status.HTTP_404_NOT_FOUND,
        )
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession):
        doc = await _fetch_document(session, doc_id)
        await audit.append(
            session,
            action="document.delete",
            outcome="allowed",
            target_type="document",
            target_id=str(doc_id),
            **snapshot,
        )
        await session.delete(doc)
        await session.flush()

    try:
        await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
