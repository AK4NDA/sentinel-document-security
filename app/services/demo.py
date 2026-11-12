"""Demo cast seeding for local walkthroughs (spec 0011).

`seed-demo` is the only path that creates the demo admin. It refuses to run
unless ENV is dev so the public demo credentials can never land in a real
environment.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.demo_constants import DEMO_USERS, DemoUser
from app.models import User
from app.security import totp as totp_security
from app.security.passwords import hash_password_async
from app.services import audit


class SeedEnvRefused(RuntimeError):
    """Raised when seed-demo runs outside ENV=dev."""


@dataclass(frozen=True)
class SeedResult:
    username: str
    status: str  # "created" | "repaired" | "exists"


async def _repair(session: AsyncSession, user: User, demo: DemoUser) -> list[str]:
    """Top up drifted fields back to the constants; return repaired field names."""
    repaired: list[str] = []
    if user.role != demo.role:
        user.role = demo.role
        repaired.append("role")
    if user.clearance != demo.clearance:
        user.clearance = demo.clearance
        repaired.append("clearance")
    if not user.is_active:
        user.is_active = True
        repaired.append("is_active")

    enrolled = user.totp_enabled_at is not None
    secret_matches = False
    if user.totp_secret_encrypted is not None:
        try:
            secret_matches = (
                totp_security.open_secret(user.totp_secret_encrypted) == demo.totp_secret
            )
        except Exception:
            secret_matches = False
    if not enrolled or not secret_matches:
        user.totp_secret_encrypted = totp_security.seal_secret(demo.totp_secret)
        if user.totp_enabled_at is None:
            user.totp_enabled_at = datetime.now(UTC)
        user.totp_last_counter = None
        repaired.append("totp")

    if repaired:
        await audit.append(
            session,
            action="user.update",
            outcome="allowed",
            target_type="user",
            target_id=str(user.id),
            details={"via": "seed-demo", "repaired": sorted(repaired)},
        )
    return repaired


async def seed_demo(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[SeedResult]:
    """Create or repair the demo cast in one transaction; idempotent."""
    if get_settings().env != "dev":
        raise SeedEnvRefused("seed-demo only runs when ENV is dev")

    results: list[SeedResult] = []
    async with session_factory() as session:
        stmt = select(User).where(User.username.in_([u.username for u in DEMO_USERS]))
        existing = {u.username: u for u in (await session.execute(stmt)).scalars()}
        for demo in DEMO_USERS:
            user = existing.get(demo.username)
            if user is None:
                user = User(
                    username=demo.username,
                    email=demo.email,
                    display_name=demo.display_name,
                    password_hash=await hash_password_async(demo.password),
                    role=demo.role,
                    clearance=demo.clearance,
                    is_active=True,
                    totp_secret_encrypted=totp_security.seal_secret(demo.totp_secret),
                    totp_enabled_at=datetime.now(UTC),
                )
                session.add(user)
                await session.flush()
                await audit.append(
                    session,
                    action="user.create",
                    outcome="allowed",
                    target_type="user",
                    target_id=str(user.id),
                    details={
                        "via": "seed-demo",
                        "role": demo.role.value,
                        "clearance": demo.clearance.name,
                    },
                )
                results.append(SeedResult(demo.username, "created"))
            else:
                repaired = await _repair(session, user, demo)
                results.append(SeedResult(demo.username, "repaired" if repaired else "exists"))
        await session.commit()
    return results
