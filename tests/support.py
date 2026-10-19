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
sqlite_only = unittest.skipIf(
    bool(postgres_url()), "SQLite file test; not applicable to PostgreSQL"
)


def strip_smart_schema(db):
    """Build an actual pre-13 fixture before testing earlier upgrade steps."""
    strip_monitor_schema(db)
    for table in ("smart_sessions", "smart_exits", "smart_gateway"):
        db.execute(f"DROP TABLE {table}")
    for table, columns in (
        ("dns_accounts", ("relay_enabled", "relay_limit", "relay_connections")),
        ("dns_periods", ("relay_up", "relay_down", "relay_sessions", "relay_errors")),
    ):
        for column in columns:
            db.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


def strip_monitor_schema(db):
    """Build an actual pre-14 fixture without orphaning monitoring consent."""
    strip_wireguard_schema(db)
    db.execute("DROP TABLE tunnel_monitors")
    db.execute("DROP TABLE tunnel_monitor_runtime")


def strip_wireguard_schema(db):
    strip_openvpn_schema(db)
    db.execute("DROP TABLE wg_peers")
    db.execute("DROP TABLE wg_endpoints")
    db.execute("DROP TABLE wg_runtime")


def strip_openvpn_schema(db):
    db.execute("DROP TABLE ovpn_peers")
    db.execute("DROP TABLE ovpn_endpoints")
    db.execute("DROP TABLE ovpn_runtime")
