"""Seed explicit development/demo records."""
from sentinel.config import settings
from sentinel.database import Database
from sentinel.security import CredentialVault
from sentinel.seed import seed_demo

database = Database(settings.database_path)
seed_demo(database, settings, CredentialVault(settings.encryption_key))
print("Development seed data ready")
