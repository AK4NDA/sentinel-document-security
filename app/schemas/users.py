from pydantic import BaseModel, Field, field_validator, model_validator

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
