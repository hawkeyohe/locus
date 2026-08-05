"""Create or upgrade the Locus SQLite schema."""
from sentinel.config import settings
from sentinel.database import Database

Database(settings.database_dsn)
print("Schema ready")
