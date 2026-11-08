"""Account lockout policy shared by login, MFA verify, and enroll confirm."""

from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.models import User


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def is_locked(user: User, now: datetime | None = None) -> bool:
    if user.locked_until is None:
        return False
    return _aware(user.locked_until) > (now or datetime.now(UTC))


def retry_after_seconds(user: User, now: datetime | None = None) -> int:
    if user.locked_until is None:
        return 0
    remaining = _aware(user.locked_until) - (now or datetime.now(UTC))
    return max(0, int(remaining.total_seconds()))


def record_failure(user: User, now: datetime | None = None) -> None:
    settings = get_settings()
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.login_max_attempts:
        user.locked_until = (now or datetime.now(UTC)) + timedelta(
            seconds=settings.login_lockout_seconds
        )


def record_success(user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
