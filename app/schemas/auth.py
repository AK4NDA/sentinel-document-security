import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models import ClassificationLevel, UserRole


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class MfaRequiredResponse(BaseModel):
    mfa_required: Literal[True] = True
    pending_token: str
    expires_in: int


class MfaVerifyRequest(BaseModel):
    pending_token: str = Field(min_length=1, max_length=512)
    code: str = Field(min_length=6, max_length=6)


class MfaEnrollConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MfaEnrollStartResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg: str


class UserProfile(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    display_name: str | None
    role: UserRole
    clearance: ClassificationLevel
    is_active: bool
    mfa_enrolled: bool
    created_at: datetime

    model_config = {"from_attributes": True}
