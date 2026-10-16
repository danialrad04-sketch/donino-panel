import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import sqlite_only
from app.db import initialize, database, SCHEMA_VERSION


@sqlite_only
class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "donino.db"
        self.env = patch.dict(os.environ, {"DONINO_DB": str(self.path)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def legacy(self):
        with sqlite3.connect(self.path) as db:
            db.executescript((Path(__file__).parent / "fixtures/v0.1.sql").read_text())
            db.execute(
                "INSERT INTO users(id,credential,name,used,token,created) VALUES(?,?,?,?,?,?)",
                (
                    "u-1",
                    "old-secret-credential",
                    "old-user",
                    321,
                    "old-subscription-token",
                    123,
                ),
            )
            db.execute(
                "INSERT INTO nodes(id,name,host,token) VALUES(?,?,?,?)",
                ("n-1", "node", "example.com", "node-token-hash"),
            )

    def test_upgrade_keeps_identity_totals_and_creates_restorable_backup(self):
        self.legacy()
        initialize()
        with database() as db:
            user = db.execute("SELECT * FROM users").fetchone()
            self.assertEqual(
                (
                    user["used"],
                    user["legacy_used"],
                    user["uploaded"],
                    user["downloaded"],
                ),
                (321, 321, 0, 0),
            )
            self.assertEqual(user["credential"], "old-secret-credential")
            self.assertEqual(user["token"], "old-subscription-token")
            self.assertEqual(
                db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
            )
        backups = list(self.path.parent.glob("*.pre-v2-*.db"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(backups[0]) as backup:
            self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(
                backup.execute("SELECT used FROM users").fetchone()[0], 321
            )
            self.assertNotIn(
                "legacy_used",
                [r[1] for r in backup.execute("PRAGMA table_info(users)")],
            )
        initialize()
        self.assertEqual(list(self.path.parent.glob("*.pre-v2-*.db")), backups)

    def test_backup_failure_aborts_before_schema_changes(self):
        self.legacy()
        with patch("app.db.migration_backup", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                initialize()
        with sqlite3.connect(self.path) as db:
            self.assertNotIn(
                "uploaded", [r[1] for r in db.execute("PRAGMA table_info(users)")]
            )
            self.assertEqual(db.execute("SELECT used FROM users").fetchone()[0], 321)

    def test_future_database_refused(self):
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(RuntimeError):
            initialize()

    def test_fresh_database_needs_no_migration_backup(self):
        initialize()
        self.assertEqual(list(self.path.parent.glob("*.pre-v2-*.db")), [])

    def test_incompatible_development_schema_is_refused_without_changes(self):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE alembic_version(version_num TEXT PRIMARY KEY)")
            db.execute("INSERT INTO alembic_version VALUES('0001_foundation')")
        with self.assertRaisesRegex(RuntimeError, "explicit migration"):
            initialize()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(
                db.execute("SELECT version_num FROM alembic_version").fetchone()[0],
                "0001_foundation",
            )
            self.assertIsNone(
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name='users'"
                ).fetchone()
            )
