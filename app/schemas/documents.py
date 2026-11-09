import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models import ClassificationLevel


class DocumentMeta(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    owner_id: uuid.UUID
    classification: ClassificationLevel
    created_at: datetime
    updated_at: datetime


class DocumentListResponse(BaseModel):
    documents: list[DocumentMeta]


class SearchResponse(BaseModel):
    documents: list[DocumentMeta]
    total: int
    limit: int
    offset: int


class VersionMeta(BaseModel):
    version_number: int
    classification: ClassificationLevel
    size_bytes: int
    mime_type: str
    created_by: str
    created_at: datetime
    is_current: bool


class VersionListResponse(BaseModel):
    versions: list[VersionMeta]


class DocumentUploadForm(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=2000)
