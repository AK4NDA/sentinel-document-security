"""Management CLI: `python -m app create-admin ...` (spec 0003 AC-16)."""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models import ClassificationLevel, User, UserRole
from app.security.passwords import hash_password_async
from app.services import audit


async def _create_admin(args: argparse.Namespace) -> int:
    password = getpass.getpass("Password: ")
    if len(password) < 12:
        print("password must be at least 12 characters", file=sys.stderr)
        return 2
    if getpass.getpass("Confirm password: ") != password:
        print("passwords do not match", file=sys.stderr)
        return 2

    async with SessionLocal() as session:
        existing = await session.execute(
            select(User).where((User.username == args.username) | (User.email == args.email))
        )
        if existing.scalar_one_or_none() is not None:
            print("username or email already exists", file=sys.stderr)
            return 1
        user = User(
            username=args.username,
            email=args.email,
            password_hash=await hash_password_async(password),
            role=UserRole.ADMIN,
            clearance=ClassificationLevel(args.clearance),
            display_name=args.display_name,
            is_active=True,
        )
        session.add(user)
        try:
            await session.flush()
            await audit.append(
                session,
                action="user.create",
                outcome="allowed",
                target_type="user",
                target_id=str(user.id),
                details={"via": "cli", "role": "admin"},
            )
            await session.commit()
        except IntegrityError:
            await session.rollback()
            print("username or email already exists", file=sys.stderr)
            return 1
    print(f"created admin user {args.username}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an administrator account")
    admin.add_argument("--username", required=True)
    admin.add_argument("--email", required=True)
    admin.add_argument("--clearance", type=int, default=1, choices=range(1, 6))
    admin.add_argument("--display-name", default=None)
    args = parser.parse_args(argv)
    if args.command == "create-admin":
        return asyncio.run(_create_admin(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
