import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.db import database, hash_password
from app.main import app
from app.security import totp
from app.storage import backup_database, import_sqlite


class FoundationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_DB": self.tmp.name + "/db.sqlite",
                "DONINO_DATABASE_URL": "",
                "DONINO_KEY_FILE": self.tmp.name + "/master.key",
                "DONINO_SECURE_COOKIE": "false",
            },
        )
        self.env.start()
        self.client = TestClient(app).__enter__()
        self.headers = {"X-Donino": "1"}
        with database() as db:
            db.execute(
                "INSERT INTO admins VALUES(?,?,?)",
                ("owner", hash_password("long-test-password"), "owner"),
            )
        self.login()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.tmp.cleanup()

    def post(self, path, body=None, headers=None):
        return self.client.post(
            "/api" + path, json=body, headers=headers or self.headers
        )

    def login(self, **extra):
        return self.post(
            "/login", {"username": "owner", "password": "long-test-password", **extra}
        )

    def user(self, name="one"):
        response = self.post("/users", {"name": name})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def node(self):
        return self.post("/nodes", {"name": "test", "host": "example.com"}).json()

    def inbound(self, node):
        result = self.post(
            "/inbounds",
            {
                "name": "reality",
                "node_id": node["id"],
                "protocol": "vless",
                "port": 2443,
                "sni": "example.com",
            },
        )
        self.assertEqual(result.status_code, 201, result.text)

    def config(self, node):
        return self.client.get(
            "/api/agent/config", headers={"Authorization": "Bearer " + node["token"]}
        ).json()

    def test_device_secrets_profiles_and_independent_revocation(self):
        uid, node = self.user(), self.node()
        self.inbound(node)
        device = self.post(f"/users/{uid}/devices", {"name": "Phone"}).json()
        config = self.config(node)
        clients = config["config"]["inbounds"][1]["settings"]["clients"]
        self.assertEqual(len(clients), 2)
        self.assertEqual(len({c["id"] for c in clients}), 2)
        url = self.client.get(f"/api/users/{uid}/subscription").json()["url"]
        profiles = self.client.get(url + "?format=raw").text
        for client in clients:
            self.assertIn(client["id"], profiles)
        self.assertNotIn("secret", self.client.get(f"/api/users/{uid}/devices").text)
        other_uid = self.user("two")
        self.assertEqual(
            self.client.put(
                f"/api/users/{other_uid}/devices/{device['id']}",
                headers=self.headers,
                json={"name": "stolen", "enabled": False},
            ).status_code,
            404,
        )
        self.client.put(
            f"/api/users/{uid}/devices/{device['id']}",
            headers=self.headers,
            json={"name": "Phone", "enabled": False},
        )
        after = self.config(node)["config"]["inbounds"][1]["settings"]["clients"]
        self.assertNotIn(device["id"], [c["email"] for c in after])
        self.assertIn(uid, [c["email"] for c in after])

    def test_selective_node_assignment_also_filters_subscription(self):
        one, two, node = self.user(), self.user("two"), self.node()
        self.inbound(node)
        response = self.client.put(
            f"/api/nodes/{node['id']}/assignments",
            headers=self.headers,
            json={"mode": "selected", "user_ids": [one]},
        )
        self.assertEqual(response.status_code, 200)
        clients = self.config(node)["config"]["inbounds"][1]["settings"]["clients"]
        self.assertEqual([c["email"] for c in clients], [one])
        url = self.client.get(f"/api/users/{two}/subscription").json()["url"]
        self.assertEqual(self.client.get(url + "?format=raw").text, "")

    def test_late_explicit_period_usage_does_not_charge_new_period(self):
        uid, node = self.user(), self.node()
        period = self.client.get(f"/api/users/{uid}/periods").json()[0]["id"]
        headers = {"Authorization": "Bearer " + node["token"]}

        def send(up):
            return self.post(
                "/agent/heartbeat",
                {
                    "epoch": "old-process",
                    "usage": [
                        {"user_id": uid, "period_id": period, "up": up, "down": 0}
                    ],
                },
                headers,
            )

        self.assertEqual(send(50).status_code, 200)
        self.assertEqual(self.post(f"/users/{uid}/reset-traffic").status_code, 200)
        self.assertEqual(send(70).status_code, 200)
        self.assertEqual(send(70).status_code, 200)
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 0)
        periods = self.client.get(f"/api/users/{uid}/periods").json()
        self.assertEqual(next(p["uploaded"] for p in periods if p["id"] == period), 70)

    def test_totp_rfc_vector_encrypted_seed_and_recovery_is_one_use(self):
        self.assertEqual(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1), "287082")
        setup = self.post("/security/mfa/setup", {"password": "long-test-password"})
        self.assertEqual(setup.status_code, 200)
        seed = setup.json()["secret"]
        with database() as db:
            self.assertNotIn(
                seed, db.execute("SELECT secret FROM admin_mfa").fetchone()[0]
            )
        result = self.post("/security/mfa/enable", {"code": totp(seed)})
        self.assertEqual(result.status_code, 200, result.text)
        codes = result.json()["recovery_codes"]
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(
            self.login(code=totp(seed)).status_code, 401
        )  # enable consumed this step
        self.assertEqual(self.login(recovery_code=codes[0]).status_code, 200)
        self.post("/logout")
        self.assertEqual(self.login(recovery_code=codes[0]).status_code, 401)
        self.assertEqual(self.login(recovery_code=codes[1]).status_code, 200)
        self.assertEqual(
            Path(self.tmp.name, "master.key").stat().st_mode & 0o777, 0o600
        )

    def test_scoped_expiring_token_cannot_read_profiles_or_mutate(self):
        uid = self.user()
        result = self.post(
            "/security/tokens",
            {
                "name": "automation",
                "scopes": ["users:read"],
                "expires": int(time.time()) + 300,
            },
        )
        self.assertEqual(result.status_code, 201, result.text)
        value = result.json()
        self.assertNotIn(value["token"], self.client.get("/api/security/tokens").text)
        headers = {**self.headers, "Authorization": "Bearer " + value["token"]}
        self.assertEqual(
            self.client.get("/api/users", headers=headers).status_code, 200
        )
        self.assertEqual(
            self.client.get(
                f"/api/users/{uid}/subscription", headers=headers
            ).status_code,
            403,
        )
        self.assertEqual(
            self.post("/users", {"name": "forbidden"}, headers).status_code, 403
        )
        self.assertEqual(
            self.client.get("/api/backup", headers=headers).status_code, 403
        )
        self.client.delete("/api/security/tokens/" + value["id"], headers=self.headers)
        self.assertEqual(
            self.client.get("/api/users", headers=headers).status_code, 401
        )

    def test_sqlite_import_preserves_data_and_rejects_nonempty_target(self):
        uid = self.user()
        backup = Path(self.tmp.name) / "backup.db"
        backup_database(backup)
        target = Path(self.tmp.name) / "destination.db"
        with patch.dict(os.environ, {"DONINO_DB": str(target)}):
            import_sqlite(backup)
            with database() as db:
                self.assertEqual(db.execute("SELECT id FROM users").fetchone()[0], uid)
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 3
                )
            with self.assertRaisesRegex(RuntimeError, "contains data"):
                import_sqlite(backup)

    def test_first_use_validity_starts_once_and_mfa_key_creation_is_concurrent_safe(
        self,
    ):
        from concurrent.futures import ThreadPoolExecutor

        from app.security import cipher

        with ThreadPoolExecutor(max_workers=8) as pool:
            encrypted = list(pool.map(lambda _: cipher().encrypt(b"test"), range(16)))
        self.assertTrue(all(cipher().decrypt(value) == b"test" for value in encrypted))
        result = self.post("/users", {"name": "first-use", "validity_seconds": 3600})
        self.assertEqual(result.status_code, 201)
        uid, node = result.json()["id"], self.node()
        self.assertIsNone(result.json()["expires"])
        message = {
            "epoch": "first-use",
            "usage": [{"user_id": uid, "up": 100, "down": 0}],
        }
        headers = {"Authorization": "Bearer " + node["token"]}
        before = int(time.time())
        self.assertEqual(
            self.post("/agent/heartbeat", message, headers).status_code, 200
        )
        first = self.client.get("/api/users").json()[0]["expires"]
        self.assertGreaterEqual(first, before + 3600)
        message["usage"][0]["up"] = 200
        self.post("/agent/heartbeat", message, headers)
        self.assertEqual(self.client.get("/api/users").json()[0]["expires"], first)
