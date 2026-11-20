"""Per-request metadata recorded in audit and custody entries."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    ip: str
    user_agent_hash: str

    @classmethod
    def build(cls, ip: str | None, user_agent: str | None) -> "RequestContext":
        ua = (user_agent or "")[:512]
        return cls(ip=(ip or "unknown")[:45], user_agent_hash=hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest())


SYSTEM_CONTEXT = RequestContext.build("127.0.0.1", "dems-system")
