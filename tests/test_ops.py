import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import ops
from app.db import initialize, database, hash_password


class OpsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "donino.db"
        self.env = patch.dict(os.environ, {"DONINO_DB": str(self.path), "DONINO_PUBLIC_URL": "https://panel.example.com"})
        self.env.start()
        initialize()
        with database() as db:
            db.execute("INSERT INTO admins VALUES(?,?,?)", ("owner", hash_password("long-test-password"), "owner"))
            db.execute("INSERT INTO users(id,credential,name,token,created) VALUES(?,?,?,?,?)", ("u1", "c1", "alice", "t1", 1))
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_doctor_healthy_database_exits_zero(self):
        rows, code = ops.doctor()
        self.assertEqual(code, 0, rows)
        levels = {name: level for level, name, _ in rows}
        self.assertEqual(levels["integrity_check"], "OK")
        self.assertEqual(levels["owners"], "OK")

    def test_doctor_fails_without_owner_and_warns_on_weak_settings(self):
        with database() as db:
            db.execute("UPDATE admins SET role='viewer'")
        os.environ["DONINO_PUBLIC_URL"] = "http://panel.example.com"
        os.environ["DONINO_SECURE_COOKIE"] = "false"
        rows, code = ops.doctor()
        self.assertEqual(code, 1)
        levels = {name: level for level, name, _ in rows}
        self.assertEqual(levels["owners"], "FAIL")
        self.assertEqual(levels["DONINO_PUBLIC_URL"], "WARN")
        self.assertEqual(levels["DONINO_SECURE_COOKIE"], "WARN")

    def test_doctor_never_prints_secrets(self):
        rows, _ = ops.doctor()
        text = json.dumps(rows)
        self.assertNotIn("c1", text)
        self.assertNotIn("t1", text)
        self.assertNotIn("long-test-password", text)

    def test_backup_writes_verified_manifest(self):
        dest = self.root / "b.db"
        manifest = ops.backup(dest)
        self.assertEqual(manifest["sha256"], ops._sha256(dest))
        self.assertEqual(manifest["schema_version"], 4)
        stored = json.loads((self.root / "b.db.manifest.json").read_text())
        self.assertEqual(stored, manifest)
        self.assertEqual(oct(os.stat(dest).st_mode & 0o777), "0o600")

    def test_backup_refuses_to_overwrite(self):
        dest = self.root / "b.db"
        ops.backup(dest)
        with self.assertRaises(FileExistsError):
            ops.backup(dest)

    def test_restore_requires_manifest(self):
        dest = self.root / "b.db"
        ops.backup(dest)
        (self.root / "b.db.manifest.json").unlink()
        with self.assertRaises(ValueError):
            ops.restore(dest, replace=True)

    def test_restore_rejects_tampered_backup(self):
        dest = self.root / "b.db"
        ops.backup(dest)
        with sqlite3.connect(dest) as db:
            db.execute("UPDATE users SET name='mallory'")
        with self.assertRaisesRegex(ValueError, "checksum"):
            ops.restore(dest, replace=True)

    def test_restore_rejects_future_schema(self):
        dest = self.root / "future.db"
        with sqlite3.connect(dest) as db:
            db.execute("PRAGMA user_version=99")
        os.chmod(dest, 0o600)
        manifest = {"sha256": ops._sha256(dest), "schema_version": 99}
        (self.root / "future.db.manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "newer"):
            ops.restore(dest, replace=True)

    def test_restore_replaces_and_keeps_safety_copy(self):
        dest = self.root / "b.db"
        ops.backup(dest)
        with database() as db:
            db.execute("UPDATE users SET name='changed-after-backup'")
        result = ops.restore(dest, replace=True)
        self.assertTrue(Path(result["safety_copy"]).exists())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT name FROM users").fetchone()[0], "alice")
        with sqlite3.connect(result["safety_copy"]) as db:
            self.assertEqual(db.execute("SELECT name FROM users").fetchone()[0], "changed-after-backup")

    def test_restore_refuses_existing_database_without_replace(self):
        dest = self.root / "b.db"
        ops.backup(dest)
        with self.assertRaises(FileExistsError):
            ops.restore(dest)


if __name__ == "__main__":
    unittest.main()
