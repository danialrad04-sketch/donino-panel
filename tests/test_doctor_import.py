import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

from test_accounts import PanelBase
from app.db import database
from app.doctor_import import inspect_source, stage, rollback
from app.secrets import unseal


class DoctorImportTest(PanelBase):
    def setUp(self):
        super().setUp()
        self.source = Path(self.tmp.name) / "doctor.db"
        self.instance = str(uuid.uuid4())
        self.pre = Path(self.tmp.name) / "before-import.db"
        self.undo = Path(self.tmp.name) / "before-rollback.db"
        self.password_hash = hashlib.pbkdf2_hmac(
            "sha256", b"legacy-password", bytes.fromhex("12" * 16), 200_000
        ).hex()
        with sqlite3.connect(self.source) as db:
            db.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, created_at TEXT, status TEXT, quota_bytes INTEGER, used_bytes INTEGER, quota_mode TEXT, quota_reset_at TEXT, expires_at TEXT, wallet INTEGER, speed_kbps INTEGER, max_ips INTEGER, password_hash TEXT, password_salt TEXT, template_id INTEGER);
CREATE TABLE ips(id INTEGER PRIMARY KEY,user_id INTEGER,ip TEXT UNIQUE,last_counter INTEGER,added_at TEXT);
CREATE TABLE templates(id INTEGER PRIMARY KEY,name TEXT,is_default INTEGER,created_at TEXT);
CREATE TABLE template_services(template_id INTEGER,service_key TEXT,group_key TEXT);
CREATE TABLE template_domains_off(template_id INTEGER,domain TEXT);
CREATE TABLE custom_domains(domain TEXT PRIMARY KEY,note TEXT,added_at TEXT);
CREATE TABLE transactions(id INTEGER PRIMARY KEY,user_id INTEGER,amount INTEGER,receipt_blob BLOB,status TEXT);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE ip_counters(ip TEXT,relay TEXT,last_counter INTEGER);
CREATE TABLE admin_sessions(token TEXT PRIMARY KEY,expires_at TEXT);
INSERT INTO templates VALUES(1,'default',1,'2026-01-01T00:00:00Z');
INSERT INTO templates VALUES(2,'PlayStation',0,'2026-01-01T00:00:00Z');
INSERT INTO template_services VALUES(2,'playstation','online');
INSERT INTO template_domains_off VALUES(2,'playstation.net');
INSERT INTO custom_domains VALUES('custom.example','source note','2026-01-01T00:00:00Z');
INSERT INTO settings VALUES('plan_days','30');
INSERT INTO ip_counters VALUES('1.1.1.1','relay-one',123);
INSERT INTO admin_sessions VALUES('NEVER_COPY_THIS_SESSION','2099-01-01T00:00:00Z');
""")
            for uid, name, mode, status in (
                (1, "alice", "monthly", "active"),
                (2, "bob", "oneoff", "over_quota"),
            ):
                db.execute(
                    "INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        uid,
                        name,
                        name.title(),
                        "2026-01-01T00:00:00Z",
                        status,
                        1000,
                        uid * 600,
                        mode,
                        "2026-11-01T00:00:00Z" if mode == "monthly" else None,
                        "2026-12-01T00:00:00Z",
                        500,
                        2048,
                        1,
                        self.password_hash,
                        "12" * 16,
                        uid,
                    ),
                )
                db.execute(
                    "INSERT INTO ips VALUES(?,?,?,?,?)",
                    (uid, uid, "1.1.1." + str(uid), 123, "2026-01-01T00:00:00Z"),
                )
            db.execute(
                "INSERT INTO transactions VALUES(1,1,500,?,'approved')",
                (b"private-receipt",),
            )

    def apply(self):
        snapshot = inspect_source(self.source)
        return stage(snapshot, self.instance, snapshot["fingerprint"], self.pre)

    def test_readonly_staging_preserves_source_units_credentials_and_idempotence(self):
        original = self.source.read_bytes()
        first, second = inspect_source(self.source), inspect_source(self.source)
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(original, self.source.read_bytes())
        self.assertNotIn("NEVER_COPY_THIS_SESSION", json.dumps(first["payload"]))
        self.assertEqual(first["summary"]["used_bytes"], 1800)
        result = self.apply()
        self.assertEqual(result["state"], "staged")
        self.assertTrue(self.apply()["already_staged"])
        self.assertEqual(self.pre.stat().st_mode & 0o777, 0o600)
        with database() as db:
            users = db.execute("SELECT * FROM users").fetchall()
            self.assertEqual(len(users), 2)
            self.assertTrue(
                all(
                    not r["enabled"] and r["used"] == 0 and r["quota"] == 0
                    for r in users
                )
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM dns_ip_leases").fetchone()[0], 0
            )
            archive = db.execute("SELECT payload FROM doctor_imports").fetchone()[0]
            self.assertNotIn(self.password_hash, archive)
            recovered = json.loads(unseal(archive))
            self.assertEqual(
                recovered["tables"]["users"][0]["password_hash"], self.password_hash
            )
            self.assertIn(
                "$bytes", recovered["tables"]["transactions"][0]["receipt_blob"]
            )
        metadata = self.client.get("/api/imports/doctor")
        self.assertEqual(metadata.status_code, 200)
        self.assertNotIn("payload", metadata.text)
        self.assertNotIn(self.password_hash, metadata.text)
        rows = self.client.get(f"/api/imports/doctor/{result['id']}/users").json()
        self.assertEqual(sorted(r["used_bytes"] for r in rows), [600, 1200])
        self.assertEqual(
            self.client.put(
                f"/api/users/{rows[0]['user_id']}",
                headers=self.headers,
                json={"name": rows[0]["name"], "enabled": True, "quota": 1000},
            ).status_code,
            409,
        )
        self.assertEqual(
            len(
                self.client.get(f"/api/imports/doctor/{result['id']}/templates").json()
            ),
            2,
        )
        self.login("operator")
        self.assertEqual(self.client.get("/api/imports/doctor").status_code, 403)

    def test_backup_failure_and_mid_import_conflict_commit_no_partial_users(self):
        snapshot = inspect_source(self.source)
        with patch(
            "app.doctor_import.backup", side_effect=OSError("fixture backup failure")
        ):
            with self.assertRaises(OSError):
                stage(snapshot, self.instance, snapshot["fingerprint"], self.pre)
        self.assertEqual(self.client.get("/api/users").json(), [])
        name = f"doctor-{self.instance[:8]}-2-bob"
        self.assertEqual(self.post("/users", {"name": name}).status_code, 201)
        from app.db import IntegrityErrors

        with self.assertRaises(IntegrityErrors):
            stage(snapshot, self.instance, snapshot["fingerprint"], self.pre)
        with database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM doctor_imports").fetchone()[0], 0
            )
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_rollback_is_owned_idempotent_and_refuses_changed_records(self):
        result = self.apply()
        existing = self.post("/users", {"name": "unrelated"}).json()
        self.assertEqual(rollback(result["id"], self.undo)["state"], "rolled_back")
        self.assertEqual(rollback(result["id"], self.undo)["state"], "rolled_back")
        self.assertEqual(
            [u["id"] for u in self.client.get("/api/users").json()], [existing["id"]]
        )
        with self.assertRaises(ValueError):
            self.apply()

    def test_changed_source_and_changed_target_are_not_silently_overwritten(self):
        snapshot = inspect_source(self.source)
        with sqlite3.connect(self.source) as db:
            db.execute("UPDATE users SET used_bytes=777 WHERE id=1")
        changed = inspect_source(self.source)
        with self.assertRaises(ValueError):
            stage(changed, self.instance, snapshot["fingerprint"], self.pre)
        self.assertFalse(self.pre.exists())
        result = self.apply()
        with database() as db:
            uid = db.execute(
                "SELECT user_id FROM doctor_import_users LIMIT 1"
            ).fetchone()[0]
            db.execute("UPDATE users SET name='edited' WHERE id=?", (uid,))
        with self.assertRaises(ValueError):
            rollback(result["id"], self.undo)
        self.assertFalse(self.undo.exists())
        with database() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)

    def test_unknown_hash_catalog_group_and_ambiguous_ip_are_refused_readonly(self):
        with sqlite3.connect(self.source) as db:
            db.execute("UPDATE users SET password_hash='argon2-unknown' WHERE id=1")
        with self.assertRaisesRegex(ValueError, "Unknown password"):
            inspect_source(self.source)
        with sqlite3.connect(self.source) as db:
            db.execute("UPDATE users SET password_hash=?", (self.password_hash,))
            db.execute("UPDATE template_services SET group_key='unknown'")
        with self.assertRaisesRegex(ValueError, "Unknown template"):
            inspect_source(self.source)
        with sqlite3.connect(self.source) as db:
            db.execute("UPDATE template_services SET group_key='online'")
            db.execute("UPDATE ips SET ip='::ffff:1.1.1.1' WHERE id=2")
        with self.assertRaisesRegex(ValueError, "ownership conflict"):
            inspect_source(self.source)
        self.assertEqual(self.client.get("/api/users").json(), [])
