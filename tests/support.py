"""Shared test setup.

By default every test gets a fresh SQLite file. Set DONINO_TEST_DATABASE_URL to a
PostgreSQL URL to run the same tests against PostgreSQL; the public schema is
dropped and recreated before each test, so that URL must point at a disposable database.
"""

import os
import unittest
from pathlib import Path


def postgres_url():
    return os.environ.get("DONINO_TEST_DATABASE_URL", "").strip()


def configure(folder, name="panel.db"):
    os.environ["DONINO_DB"] = str(Path(folder) / name)
    url = postgres_url()
    if url:
        import psycopg

        os.environ["DONINO_DATABASE_URL"] = url
        with psycopg.connect(url, autocommit=True) as raw:
            raw.execute("DROP SCHEMA public CASCADE")
            raw.execute("CREATE SCHEMA public")
    else:
        os.environ.pop("DONINO_DATABASE_URL", None)


# Tests that open the SQLite file directly (or test SQLite-only migration paths).
sqlite_only = unittest.skipIf(bool(postgres_url()), "SQLite file test; not applicable to PostgreSQL")
