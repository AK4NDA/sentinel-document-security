import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import ClassificationLevel, UserRole
from app.schemas.auth import UserProfile


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)
    role: UserRole
    clearance: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    display_name: str | None = Field(default=None, max_length=200)

    @field_validator("email")
    @classmethod
    def email_has_at(cls, value: str) -> str:
        if "@" not in value:
            raise ValueError("email must contain @")
        return value


class UserAdminCreate(UserCreate):
    @model_validator(mode="after")
    def role_is_not_admin(self):
        if self.role == UserRole.ADMIN:
            raise ValueError("admin accounts cannot be created via the API")
        return self


class UserListResponse(BaseModel):
    users: list[UserProfile]


class UserAdminPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole | None = None
    clearance: ClassificationLevel | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in ("role", "clearance"):
                if key in data and data[key] is None:
                    raise ValueError(f"{key} cannot be null")
        return data

    @model_validator(mode="after")
    def at_least_one_field(self):
        if self.role is None and self.clearance is None:
            raise ValueError("provide role or clearance")
        return self


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


class UserLookupOut(BaseModel):
    id: uuid.UUID
    username: str


class UserLookupResponse(BaseModel):
    users: list[UserLookupOut]
