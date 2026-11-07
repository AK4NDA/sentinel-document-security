"""Deny by default policy checks (spec 0003 security model)."""

from app.models import ClassificationLevel, User, UserRole

OFFICER_ROLE = UserRole.USER


def can_access_documents(user: User) -> bool:
    return user.role == OFFICER_ROLE


def can_read(user: User, classification: int) -> bool:
    return can_access_documents(user) and user.clearance >= classification


def write_classification(user: User) -> ClassificationLevel:
    """Uploads and new versions are pinned to the writer's clearance."""
    return user.clearance
