"""Create the first administrator account.

Registration is admin-only, so the very first admin has to be created out-of-band.
Run from the backend/ folder (with the virtual environment active):

    python -m scripts.create_admin --username admin --email admin@example.org

The password is read from a hidden prompt (or the DEMS_ADMIN_PASSWORD environment variable for
automation). The account is created with must_change_password=True, so the web app asks for a
new password on first sign-in. Uses the same KEK passphrase as the server: if no key
configuration exists yet, it is created now, so use the passphrase you intend to keep.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.crypto import initialize_key_service, key_service
from app.core.security import hash_password, validate_password_policy
from app.db.models import AuditAction, Outcome, Role, User, utcnow
from app.db.session import dispose_engine, get_sessionmaker, init_db
from app.schemas.users import UserCreate
from app.services import audit_service
from app.services.context import SYSTEM_CONTEXT


async def create_admin(username: str, email: str, password: str, *, allow_additional: bool) -> User:
    await init_db()
    async with get_sessionmaker()() as db:
        admins = (await db.execute(select(func.count()).select_from(User).where(User.role == Role.ADMIN))).scalar_one()
        if admins and not allow_additional:
            raise SystemExit("An administrator already exists. Sign in and use the app, or pass --allow-additional.")
        clash = (await db.execute(select(User.id).where((User.username == username) | (User.email == email)))).first()
        if clash:
            raise SystemExit("A user with that username or email already exists.")

        pw_hash = hash_password(password)
        user = User(
            username=username, email=email, password_hash=pw_hash, role=Role.ADMIN, must_change_password=True,
            password_history=[pw_hash], password_changed_at=utcnow(),
        )
        db.add(user)
        await db.flush()
        await audit_service.record(
            db, action=AuditAction.USER_CREATE, outcome=Outcome.SUCCESS, ctx=SYSTEM_CONTEXT,
            resource_type="user", resource_id=user.id,
            details={"username": username, "role": "admin", "bootstrap": True},
        )
        await db.commit()
        return user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the first DEMS administrator.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--allow-additional", action="store_true", help="create another admin even if one exists")
    args = parser.parse_args()

    password = os.environ.get("DEMS_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Temporary password: ")
        if getpass.getpass("Repeat password: ") != password:
            raise SystemExit("Passwords do not match.")

    try:
        data = UserCreate(username=args.username, email=args.email, password=password, role=Role.ADMIN)
    except ValidationError as exc:
        raise SystemExit("Invalid input: " + "; ".join(f"{e['loc'][0]}: {e['msg']}" for e in exc.errors())) from None
    policy = validate_password_policy(data.password, username=data.username, email=data.email)
    if not policy.valid:
        raise SystemExit("Password rejected: " + " ".join(policy.errors))

    settings = get_settings()
    initialize_key_service(settings)  # unlocks (or creates) the key configuration; may prompt for the passphrase
    try:
        user = asyncio.run(create_admin(data.username, data.email, data.password, allow_additional=args.allow_additional))
        asyncio.run(dispose_engine())
    finally:
        key_service.close()
    print(f"Administrator '{user.username}' created. Sign in at the web app; you will be asked to choose a new password.")


if __name__ == "__main__":
    sys.exit(main())
