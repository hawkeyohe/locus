from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken


SECRET_KEYS = {"password", "passphrase", "secret", "token", "apikey", "api_key", "authorization", "cookie", "privatekey", "clientsecret", "accesstoken", "refreshtoken"}
VARIABLE_PATTERN = re.compile(r"{{\s*(test_input|session_id|test_run_id|test_case_id|agent_id)\s*}}")


class SecurityError(ValueError):
    pass


class CredentialVault:
    def __init__(self, key: str) -> None:
        if not key:
            raise SecurityError("LOCUS_ENCRYPTION_KEY is required")
        try:
            material = key.encode()
            if len(base64.urlsafe_b64decode(material)) != 32:
                raise ValueError
        except Exception:
            material = base64.urlsafe_b64encode(sha256(key.encode()).digest())
        self._fernet = Fernet(material)

    def encrypt(self, credentials: dict[str, str]) -> str:
        return self._fernet.encrypt(json.dumps(credentials).encode()).decode()

    def decrypt(self, ciphertext: str | None) -> dict[str, str]:
        if not ciphertext:
            return {}
        try:
            return json.loads(self._fernet.decrypt(ciphertext.encode()))
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise SecurityError("Stored credentials could not be decrypted") from exc


def mask_credentials(authentication_type: str, has_credentials: bool) -> dict[str, Any]:
    return {"authenticationType": authentication_type, "configured": has_credentials, "masked": "••••••••" if has_credentials else ""}


def _blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def validate_endpoint(url: str, allow_local: bool = False) -> tuple[str, list[str]]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise SecurityError("Endpoint must be an HTTP(S) URL without embedded credentials")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith((".local", ".internal", ".localhost")):
        if not allow_local:
            raise SecurityError("Local and internal hostnames are not allowed")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise SecurityError("Endpoint hostname could not be resolved") from exc
    if not allow_local and any(_blocked_ip(address) for address in addresses):
        raise SecurityError("Endpoint resolves to a private, reserved, or non-routable address")
    return parsed.geturl(), addresses


def substitute_template(template: Any, variables: dict[str, str]) -> Any:
    def replace(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, str):
            return VARIABLE_PATTERN.sub(lambda match: variables.get(match.group(1), ""), value)
        return value
    result = replace(template)
    json.dumps(result)
    return result


def extract_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise KeyError(f"Response path not found: {path}")
    return current


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", key.lower())
            secret_names = {re.sub(r"[^a-z]", "", name.lower()) for name in SECRET_KEYS}
            sensitive = normalized in secret_names or any(marker in normalized for marker in ("authorization", "apikey", "accesstoken", "refreshtoken", "clientsecret", "privatekey", "password", "passphrase"))
            result[key] = "[REDACTED]" if sensitive else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    blocked = {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "cookie"}
    result = {}
    for key, value in headers.items():
        if key.lower() in blocked or "\r" in key + value or "\n" in key + value:
            raise SecurityError(f"Unsafe request header: {key}")
        result[key] = value
    return result
