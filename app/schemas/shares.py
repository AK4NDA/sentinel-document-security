import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models import ClassificationLevel


class ShareCreateRequest(BaseModel):
    user_id: uuid.UUID


class ShareOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    username: str
    access_level: str
    granted_by: str
    created_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None


class ShareListResponse(BaseModel):
    shares: list[ShareOut]


class SharedDocumentOut(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    classification: ClassificationLevel
    owner: str
    shared_at: datetime


class SharedDocumentListResponse(BaseModel):
    documents: list[SharedDocumentOut]
