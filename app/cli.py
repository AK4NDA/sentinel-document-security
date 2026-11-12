"""Management CLI: `python -m app create-admin ...` (spec 0003 AC-16)."""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models import ClassificationLevel, User, UserRole
from app.security.passwords import hash_password_async
from app.services import audit
from app.services.demo import SeedEnvRefused, seed_demo
from app.services.maintenance import run_cleanup


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


async def _seed_demo(_args: argparse.Namespace) -> int:
    try:
        results = await seed_demo(SessionLocal)
    except SeedEnvRefused as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except IntegrityError:
        print("demo seed hit a uniqueness conflict; check existing users", file=sys.stderr)
        return 1
    for result in results:
        print(f"{result.status}: {result.username}")
    created = sum(1 for r in results if r.status == "created")
    repaired = sum(1 for r in results if r.status == "repaired")
    unchanged = len(results) - created - repaired
    print(f"seed-demo done: {created} created, {repaired} repaired, {unchanged} unchanged")
    return 0


async def _cleanup(args: argparse.Namespace) -> int:
    try:
        report = await run_cleanup(SessionLocal, get_settings(), dry_run=args.dry_run)
    except Exception as exc:
        print(f"cleanup run failed: {exc}", file=sys.stderr)
        return 1
    for stage, error in report.errors.items():
        print(f"  {stage}: error: {error}", file=sys.stderr)
    print("dry run" if report.dry_run else "cleanup", "complete")
    for stage, count in report.stages.items():
        verb = "would delete" if report.dry_run else "deleted"
        print(f"  {stage}: {count} {verb}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an administrator account")
    admin.add_argument("--username", required=True)
    admin.add_argument("--email", required=True)
    admin.add_argument("--clearance", type=int, default=1, choices=range(1, 6))
    admin.add_argument("--display-name", default=None)
    sub.add_parser("seed-demo", help="seed the fixed demo cast (dev only)")
    cleanup = sub.add_parser("cleanup", help="run retention cleanup once")
    cleanup.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "create-admin":
        return asyncio.run(_create_admin(args))
    if args.command == "seed-demo":
        return asyncio.run(_seed_demo(args))
    if args.command == "cleanup":
        return asyncio.run(_cleanup(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
