"""Run a durable Locus worker until interrupted."""
from sentinel.config import settings
from sentinel.database import Database
from sentinel.jobs import Worker
from sentinel.security import CredentialVault
from sentinel.service import LocusService


settings.validate()
database = Database(settings.database_dsn)
service = LocusService(database, settings, CredentialVault(settings.encryption_key))
worker = Worker(service.queue, service._execute_run, settings)
print(f"Locus worker started: {worker.worker_id}")
try:
    worker.run_forever()
except KeyboardInterrupt:
    worker.stop()
