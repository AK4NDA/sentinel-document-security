"""Full text search over encrypted extracts (spec 0008).

Candidates are filtered by clearance in SQL before any decryption; each
survivor's ``search_text`` ciphertext is opened and token matched in memory.
"""

import asyncio
import logging
import re

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Document, DocumentVersion, User
from app.schemas.documents import DocumentMeta
from app.security import encryption
from app.services import audit
from app.services.documents import to_meta

logger = logging.getLogger(__name__)

SEARCH_ACTION = "document.search"
SEARCH_PATH = "/v1/documents/search"
_TOKEN_RE = re.compile(r"\w+")


def tokenize(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.casefold()))


async def _content_tokens(version: DocumentVersion) -> set[str]:
    if version.search_text is None:
        return set()
    try:
        plaintext = await asyncio.to_thread(encryption.open_blob, version.search_text)
    except Exception:
        logger.warning("search_text decrypt failed", extra={"version_id": str(version.id)})
        return set()
    return tokenize(plaintext.decode("utf-8", errors="replace"))


def _document_tokens(doc: Document) -> set[str]:
    tokens = tokenize(doc.title)
    if doc.description:
        tokens |= tokenize(doc.description)
    return tokens


async def search(
    db: AsyncSession,
    actor: User,
    *,
    q: str,
    limit: int,
    offset: int,
) -> tuple[list[DocumentMeta], int]:
    """Return (page of DocumentMeta, total matches) for the caller's readable set."""
    terms = tokenize(q)
    if not terms:
        return [], 0

    result = await db.execute(
        select(Document)
        .join(DocumentVersion, DocumentVersion.id == Document.current_version_id)
        .options(selectinload(Document.current_version))
        .where(DocumentVersion.classification <= actor.clearance)
        .order_by(Document.updated_at.desc(), Document.id)
    )
    candidates = result.scalars().all()

    matches: list[Document] = []
    for doc in candidates:
        tokens = _document_tokens(doc)
        if doc.current_version is not None and doc.current_version.search_text is not None:
            tokens |= await _content_tokens(doc.current_version)
        if terms <= tokens:
            matches.append(doc)

    total = len(matches)
    page = matches[offset : offset + limit]
    # Build response objects before transact: a chain fork rollback expires
    # ORM state, and the retry must not touch it.
    metas = [to_meta(doc) for doc in page]
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> list[DocumentMeta]:
        await audit.append(
            session,
            action=SEARCH_ACTION,
            outcome="allowed",
            target_type="endpoint",
            target_id=SEARCH_PATH,
            details={"q": q[:200], "total": total},
            **snapshot,
        )
        return metas

    try:
        return await audit.transact(db, attempt), total
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
