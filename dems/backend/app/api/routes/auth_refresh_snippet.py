"""Hook `SERVER_BOOT_ID` into refresh token creation and `/auth/refresh` verification."""
from __future__ import annotations

from typing import Any
from app.core.boot_session import get_server_boot_id, validate_token_boot_id


def attach_boot_claim(payload: dict[str, Any]) -> dict[str, Any]:
    payload["boot_id"] = get_server_boot_id()
    return payload


def verify_refresh_boot_claim(payload: dict[str, Any]) -> None:
    validate_token_boot_id(payload.get("boot_id"))
