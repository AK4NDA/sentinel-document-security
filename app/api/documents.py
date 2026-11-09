"""Classified document endpoints (officer role only)."""

import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import limiter
from app.api.deps import require_role
from app.core.config import get_settings
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.documents import (
    DocumentListResponse,
    DocumentMeta,
    SearchResponse,
    VersionListResponse,
)
from app.services import documents as documents_service
from app.services import search as search_service

router = APIRouter(prefix="/v1/documents", tags=["documents"])

OFFICER = UserRole.USER


def _search_limit():
    settings = get_settings()
    return settings.rate_limit_search if settings.rate_limit_enabled else "1000000/minute"


@router.post("", response_model=DocumentMeta, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    title: str = Form(..., min_length=1, max_length=300),
    description: str | None = Form(default=None, max_length=2000),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.upload", OFFICER)),
):
    doc = await documents_service.upload(
        db,
        actor,
        file=file,
        title=title,
        description=description,
    )
    return documents_service.to_meta(doc)


@router.get("", response_model=DocumentListResponse)
async def list_documents(
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.list", OFFICER)),
):
    docs = await documents_service.list_own(db, actor)
    return DocumentListResponse(documents=[documents_service.to_meta(d) for d in docs])


@router.get("/search", response_model=SearchResponse)
@limiter.limit(_search_limit)
async def search_documents(
    request: Request,
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.search", OFFICER)),
):
    if not search_service.tokenize(q):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "query has no terms")
    metas, total = await search_service.search(db, actor, q=q, limit=limit, offset=offset)
    return SearchResponse(documents=metas, total=total, limit=limit, offset=offset)


@router.get("/{doc_id}", response_model=DocumentMeta)
async def get_document(
    doc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.read", OFFICER)),
):
    return await documents_service.read_meta(db, actor, doc_id)


@router.get("/{doc_id}/content")
async def get_document_content(
    doc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.download", OFFICER)),
):
    plaintext, filename, mime = await documents_service.read_content(db, actor, doc_id)
    return Response(
        content=plaintext,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(plaintext)),
        },
    )


@router.post(
    "/{doc_id}/versions",
    response_model=DocumentMeta,
    status_code=status.HTTP_201_CREATED,
)
async def create_version(
    doc_id: uuid.UUID,
    file: UploadFile = File(...),
    title: str | None = Form(default=None, max_length=300),
    description: str | None = Form(default=None, max_length=2000),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.edit", OFFICER)),
):
    doc = await documents_service.edit(
        db,
        actor,
        doc_id,
        file=file,
        title=title,
        description=description,
    )
    return documents_service.to_meta(doc)


@router.get("/{doc_id}/versions", response_model=VersionListResponse)
async def list_versions(
    doc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.versions_list", OFFICER)),
):
    return await documents_service.list_versions(db, actor, doc_id)


@router.get("/{doc_id}/versions/{version_number}/content")
async def get_version_content(
    doc_id: uuid.UUID,
    version_number: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.version_download", OFFICER)),
):
    plaintext, filename, mime = await documents_service.read_version_content(
        db, actor, doc_id, version_number
    )
    return Response(
        content=plaintext,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(plaintext)),
        },
    )


@router.post(
    "/{doc_id}/versions/{version_number}/restore",
    response_model=DocumentMeta,
    status_code=status.HTTP_201_CREATED,
)
async def restore_version(
    doc_id: uuid.UUID,
    version_number: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.version_restore", OFFICER)),
):
    doc = await documents_service.restore(db, actor, doc_id, version_number)
    return documents_service.to_meta(doc)


@router.delete("/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    doc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.delete", OFFICER)),
):
    await documents_service.delete(db, actor, doc_id)
