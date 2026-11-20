"""Shared helpers for API-level tests."""
from __future__ import annotations

import hashlib
import os
import struct
import uuid
from dataclasses import dataclass

from app.core.security import hash_password
from app.db.models import Role, User
from app.db.session import get_sessionmaker

PASSWORD = "Correct-Horse-9!xyz"

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + os.urandom(3000) + b"\xff\xd9"
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\x0d\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n" + os.urandom(100_000)
TEXT = b"Chat log exported 2026-11-10\nalice: hello\nbob: hi\n" * 50
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHI", 2, 0x3E, 1) + b"\x00" * 300


def _pe() -> bytes:
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 64)
    return bytes(header) + b"PE\x00\x00" + struct.pack("<H", 0x14C) + b"\x00" * 300


PE = _pe()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Actor:
    id: uuid.UUID
    username: str
    role: Role
    headers: dict[str, str]


async def create_user(username: str, role: Role, *, password: str = PASSWORD, must_change: bool = False) -> User:
    async with get_sessionmaker()() as db:
        user = User(
            username=username, email=f"{username}@example.org", password_hash=hash_password(password), role=role,
            must_change_password=must_change, password_history=[],
        )
        db.add(user)
        await db.commit()
        return user


async def login(client, username: str, password: str = PASSWORD, **extra) -> dict:
    r = await client.post("/auth/login", json={"username": username, "password": password, **extra})
    return r


async def make_actor(client, username: str, role: Role) -> Actor:
    user = await create_user(username, role)
    r = await login(client, username)
    assert r.status_code == 200, r.text
    return Actor(user.id, username, role, {"Authorization": f"Bearer {r.json()['access_token']}"})


async def upload(client, actor: Actor, case_id, data: bytes, filename="photo.jpg", content_type="image/jpeg",
                 client_sha: str | None = None, **form):
    return await client.post(
        "/evidence/upload",
        headers=actor.headers,
        data={"case_id": str(case_id), "client_sha256": client_sha or sha256(data), **form},
        files={"file": (filename, data, content_type)},
    )


async def make_case(client, actor: Actor, number: str = "CASE-001") -> dict:
    r = await client.post("/cases", headers=actor.headers, json={"case_number": number, "title": "Test case"})
    assert r.status_code == 201, r.text
    return r.json()
