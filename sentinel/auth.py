from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from .database import Database, new_id, now


class AuthenticationError(PermissionError):
    pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < 12: raise ValueError("Password must be at least 12 characters")
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded: return False
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$")
        if algorithm != "scrypt": return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD_HASH = hash_password("locus-dummy-password-value")


class SessionService:
    def __init__(self, db: Database) -> None: self.db = db

    def signup(self, name: str, email: str, password: str, organization_name: str) -> tuple[dict[str, Any], str]:
        name, email, organization_name = name.strip(), email.strip().lower(), organization_name.strip()
        if not name or len(name) > 120: raise ValueError("Name is required and must be 120 characters or fewer")
        if not organization_name or len(organization_name) > 120: raise ValueError("Organization name is required and must be 120 characters or fewer")
        if len(email) > 254 or "@" not in email or email.startswith("@") or email.endswith("@"): raise ValueError("Enter a valid email address")
        if self.db.one("SELECT id FROM users WHERE lower(email)=?", (email,)): raise ValueError("An account with this email already exists")
        password_hash = hash_password(password); timestamp, org_id, user_id = now(), new_id("org"), new_id("user")
        self.db.insert("organizations", {"id":org_id,"name":organization_name,"plan":"starter","created_at":timestamp,"updated_at":timestamp})
        self.db.insert("users", {"id":user_id,"name":name,"email":email,"organization_id":org_id,"password_hash":password_hash,"role":"owner","created_at":timestamp,"updated_at":timestamp})
        return self.create(user_id)

    def login(self, email: str, password: str) -> tuple[dict[str, Any], str]:
        user = self.db.one("SELECT * FROM users WHERE lower(email)=?", (email.strip().lower(),))
        valid = verify_password(password, user.get("password_hash") if user else DUMMY_PASSWORD_HASH)
        if not user or not valid: raise AuthenticationError("Invalid email or password")
        return self.create(user["id"])

    def create(self, user_id: str) -> tuple[dict[str, Any], str]:
        user = self.db.one("SELECT u.*,o.name AS organization_name FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.id=?", (user_id,))
        if not user: raise AuthenticationError("User not found")
        token = secrets.token_urlsafe(48); expires = (datetime.now(UTC)+timedelta(days=14)).isoformat()
        self.db.insert("auth_sessions", {"id":new_id("session"),"user_id":user_id,"token_hash":hash_token(token),"expires_at":expires,"last_used_at":None,"revoked_at":None,"created_at":now()})
        return self.public_user(user), token

    def authenticate(self, token: str | None) -> dict[str, Any]:
        if not token: raise AuthenticationError("Sign in is required")
        record = self.db.one("SELECT s.*,u.name,u.email,u.organization_id,u.role,o.name AS organization_name FROM auth_sessions s JOIN users u ON u.id=s.user_id JOIN organizations o ON o.id=u.organization_id WHERE s.token_hash=? AND s.revoked_at IS NULL", (hash_token(token),))
        if not record or datetime.fromisoformat(record["expires_at"]) <= datetime.now(UTC): raise AuthenticationError("Session has expired")
        self.db.execute("UPDATE auth_sessions SET last_used_at=? WHERE id=?", (now(),record["id"])); return self.public_user(record)

    def revoke(self, token: str | None) -> None:
        if token: self.db.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=?", (now(),hash_token(token)))

    @staticmethod
    def public_user(user: dict[str, Any]) -> dict[str, Any]:
        return {"id":user.get("user_id",user["id"]),"name":user["name"],"email":user["email"],"organizationId":user["organization_id"],"organizationName":user["organization_name"],"role":user.get("role","owner")}


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
