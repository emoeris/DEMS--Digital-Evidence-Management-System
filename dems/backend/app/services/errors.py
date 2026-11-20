"""Service-layer errors. The API layer turns these into JSON responses."""
from __future__ import annotations


class ServiceError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def not_found(what: str = "Resource") -> ServiceError:
    return ServiceError(404, "not_found", f"{what} not found.")


def forbidden(message: str = "You do not have permission to perform this action.") -> ServiceError:
    return ServiceError(403, "forbidden", message)


def unauthorized(code: str = "invalid_credentials", message: str = "Authentication failed.") -> ServiceError:
    return ServiceError(401, code, message)


def conflict(code: str, message: str) -> ServiceError:
    return ServiceError(409, code, message)


def bad_request(code: str, message: str, status_code: int = 400) -> ServiceError:
    return ServiceError(status_code, code, message)
