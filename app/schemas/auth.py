import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models import ClassificationLevel, UserRole


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserProfile(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    display_name: str | None
    role: UserRole
    clearance: ClassificationLevel
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
