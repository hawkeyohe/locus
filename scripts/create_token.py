"""Issue an API bearer token. The plaintext token is printed exactly once."""
from __future__ import annotations

import argparse

from sentinel.auth import TokenService
from sentinel.config import settings
from sentinel.database import Database


parser = argparse.ArgumentParser()
parser.add_argument("user_id")
parser.add_argument("--name", default="CLI token")
parser.add_argument("--expires-at", default=None, help="ISO-8601 timestamp")
args = parser.parse_args()

token = TokenService(Database(settings.database_dsn)).issue(args.user_id, args.name, args.expires_at)
print("Store this token securely; it cannot be shown again:")
print(token)
