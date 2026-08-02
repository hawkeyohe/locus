"""Create or upgrade the Locus SQLite schema."""
from sentinel.config import settings
from sentinel.database import Database

Database(settings.database_path)
print(f"Schema ready: {settings.database_path}")
