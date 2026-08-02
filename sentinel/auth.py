from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime
from typing import Any

from .database import Database, new_id, now


class AuthenticationError(PermissionError):
    pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def issue(self, user_id: str, name: str = "API token", expires_at: str | None = None) -> str:
        if not self.db.one("SELECT id FROM users WHERE id=?", (user_id,)):
            raise AuthenticationError("User not found")
        token = f"locus_{secrets.token_urlsafe(32)}"
        self.db.insert("api_tokens", {"id": new_id("token"), "user_id": user_id, "name": name, "token_hash": hash_token(token), "expires_at": expires_at, "last_used_at": None, "revoked_at": None, "created_at": now()})
        return token

    def authenticate(self, authorization: str | None) -> dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationError("Bearer authentication is required")
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise AuthenticationError("Bearer authentication is required")
        record = self.db.one("SELECT t.*,u.name AS user_name,u.email,u.organization_id FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.revoked_at IS NULL", (hash_token(token),))
        if not record:
            raise AuthenticationError("Invalid or revoked access token")
        if record["expires_at"]:
            expires = datetime.fromisoformat(record["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= datetime.now(UTC):
                raise AuthenticationError("Access token has expired")
        self.db.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now(), record["id"]))
        return {"id": record["user_id"], "name": record["user_name"], "email": record["email"], "organization_id": record["organization_id"]}

    def revoke(self, user_id: str, token_id: str) -> None:
        if not self.db.execute("UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=?", (now(), token_id, user_id)):
            raise AuthenticationError("Token not found")
