"""Classified document endpoints (officer role only)."""

import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Path,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.documents import (
    DocumentListResponse,
    DocumentMeta,
    VersionListResponse,
)
from app.services import documents as documents_service

router = APIRouter(prefix="/v1/documents", tags=["documents"])

OFFICER = UserRole.USER


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
