"""Optional real PostgreSQL suite; CI supplies an isolated service database."""

import os
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy.engine import make_url

from app.db import database, hash_password, initialize
from app.identity import ensure_identity
from app.main import app
from app.storage import backup_database, import_sqlite, restore_archive


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_POSTGRES"), "DONINO_TEST_POSTGRES not configured"
)
class PostgresTest(unittest.TestCase):
    def setUp(self):
        self.base = os.environ["DONINO_TEST_POSTGRES"]
        self.schemas = []
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_DATABASE_URL": self.schema(),
                "DONINO_DB": self.tmp.name + "/unused.db",
                "DONINO_SECURE_COOKIE": "false",
            },
        )
        self.env.start()
        initialize()

    def schema(self):
        name = "test_" + uuid.uuid4().hex
        with psycopg.connect(
            self.base.replace("postgresql+psycopg://", "postgresql://"), autocommit=True
        ) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        self.schemas.append(name)
        return (
            make_url(self.base)
            .set(drivername="postgresql+psycopg")
            .update_query_dict({"options": "-csearch_path=" + name})
            .render_as_string(hide_password=False)
        )

    def tearDown(self):
        self.env.stop()
        with psycopg.connect(
            self.base.replace("postgresql+psycopg://", "postgresql://"), autocommit=True
        ) as connection:
            for name in self.schemas:
                connection.execute(
                    sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name))
                )
        self.tmp.cleanup()

    def test_actual_api_and_concurrent_usage_on_postgres(self):
        with TestClient(app) as client:
            with database() as db:
                db.execute(
                    "INSERT INTO admins VALUES(?,?,?)",
                    ("owner", hash_password("long-test-password"), "owner"),
                )
            headers = {"X-Donino": "1"}
            self.assertEqual(
                client.post(
                    "/api/login",
                    headers=headers,
                    json={"username": "owner", "password": "long-test-password"},
                ).status_code,
                200,
            )
            user = client.post(
                "/api/users",
                headers=headers,
                json={"name": "pg-user", "quota": 50_000_000_000},
            ).json()
            node = client.post(
                "/api/nodes",
                headers=headers,
                json={"name": "pg-node", "host": "example.com"},
            ).json()

            def report(_):
                return client.post(
                    "/api/agent/heartbeat",
                    headers={"Authorization": "Bearer " + node["token"]},
                    json={
                        "epoch": "pg-real",
                        "usage": [
                            {"user_id": user["id"], "up": 4_000_000_000, "down": 2}
                        ],
                    },
                ).status_code

            with ThreadPoolExecutor(max_workers=4) as pool:
                self.assertEqual(list(pool.map(report, range(8))), [200] * 8)
            self.assertEqual(client.get("/api/users").json()[0]["used"], 4_000_000_002)
            self.assertEqual(
                client.delete("/api/users/" + user["id"], headers=headers).status_code,
                200,
            )
            with database() as db:
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM user_state").fetchone()[0], 0
                )
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0
                )

    def test_sqlite_to_postgres_preserves_identity_secret_and_legacy_usage(self):
        source = Path(self.tmp.name) / "source.db"
        with patch.dict(
            os.environ, {"DONINO_DATABASE_URL": "", "DONINO_DB": str(source)}
        ):
            initialize()
            with database() as db:
                db.execute(
                    "INSERT INTO users(id,credential,name,token,created,used,legacy_used) VALUES(?,?,?,?,?,?,?)",
                    (
                        "old-id",
                        "same-secret",
                        "old-user",
                        "same-token",
                        123,
                        4_000_000_001,
                        4_000_000_001,
                    ),
                )
                ensure_identity(db, db.execute("SELECT * FROM users").fetchone())
        import_sqlite(source)
        with database() as db:
            user = db.execute("SELECT * FROM users").fetchone()
            self.assertEqual(
                (
                    user["id"],
                    user["credential"],
                    user["token"],
                    user["used"],
                    user["legacy_used"],
                ),
                ("old-id", "same-secret", "same-token", 4_000_000_001, 4_000_000_001),
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 3
            )
        with self.assertRaisesRegex(RuntimeError, "contains data"):
            import_sqlite(source)

    def test_repeatable_read_backup_and_restore_in_another_schema(self):
        with database() as db:
            db.execute(
                "INSERT INTO admins VALUES(?,?,?)",
                ("owner", hash_password("long-test-password"), "owner"),
            )
            db.execute(
                "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
                (1, "test", "first", ""),
            )
        archive = Path(self.tmp.name) / "backup.zip"
        self.assertEqual(backup_database(archive), "donino-zip")
        destination = self.schema()
        with patch.dict(os.environ, {"DONINO_DATABASE_URL": destination}):
            restore_archive(archive)
            with database() as db:
                self.assertEqual(
                    db.execute("SELECT username FROM admins").fetchone()[0], "owner"
                )
                db.execute(
                    "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
                    (2, "test", "second", ""),
                )
                self.assertEqual(
                    db.execute("SELECT COUNT(DISTINCT id) FROM audit").fetchone()[0], 2
                )
            with self.assertRaisesRegex(RuntimeError, "contains data"):
                restore_archive(archive)
