import base64
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
from support import configure, postgres_url, sqlite_only
from app.main import app
from app.db import database, hash_password
from agent.main import parse_stats


class PanelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = dict(os.environ)
        configure(self.tmp.name)
        os.environ["DONINO_SECURE_COOKIE"] = "false"
        self.client = TestClient(app)
        self.client.__enter__()
        with database() as db:
            for role in ("owner", "operator", "viewer"):
                db.execute(
                    "INSERT INTO admins VALUES(?,?,?)",
                    (role, hash_password("long-test-password"), role),
                )
        self.headers = {"X-Donino": "1"}
        self.login()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self.old)
        self.tmp.cleanup()

    def login(self, role="owner"):
        return self.client.post(
            "/api/login",
            headers=self.headers,
            json={"username": role, "password": "long-test-password"},
        )

    def post(self, path, body=None):
        return self.client.post("/api" + path, headers=self.headers, json=body)

    def user(self, **values):
        response = self.post("/users", {"name": "test-user", **values})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def node(self):
        response = self.post("/nodes", {"name": "Frankfurt", "host": "example.com"})
        self.assertEqual(response.status_code, 201)
        return response.json()

    def heartbeat(self, token, user, up, down, epoch="process-1"):
        return self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": "Bearer " + token},
            json={"epoch": epoch, "usage": [{"user_id": user, "up": up, "down": down}]},
        )

    def test_auth_csrf_session_logout(self):
        self.assertNotIn("password", self.client.get("/api/me").text)
        self.assertEqual(
            self.client.post("/api/users", json={"name": "x"}).status_code, 403
        )
        self.assertEqual(
            self.client.post(
                "/api/users",
                json={"name": "x"},
                headers={**self.headers, "Origin": "https://evil.example"},
            ).status_code,
            403,
        )
        self.post("/logout")
        self.assertEqual(self.client.get("/api/users").status_code, 401)
        self.assertEqual(self.client.get("/api/openapi.json").status_code, 401)

    def test_role_boundaries(self):
        self.login("viewer")
        self.assertEqual(self.post("/users", {"name": "x"}).status_code, 403)
        self.assertEqual(self.client.get("/api/users").status_code, 200)
        self.assertEqual(self.client.get("/api/backup").status_code, 403)
        self.login("operator")
        self.user()
        self.assertEqual(
            self.post("/nodes", {"name": "x", "host": "example.com"}).status_code, 403
        )
        self.assertEqual(self.client.get("/api/audit").status_code, 403)

    def test_rate_limit(self):
        for _ in range(10):
            self.assertEqual(
                self.post(
                    "/login", {"username": "absent", "password": "wrong"}
                ).status_code,
                401,
            )
        self.assertEqual(self.login().status_code, 429)

    def test_unique_user_and_validation(self):
        self.user()
        self.assertNotIn("credential", self.client.get("/api/users").text)
        self.assertEqual(self.post("/users", {"name": "test-user"}).status_code, 409)
        self.assertEqual(self.post("/users", {"name": "<script>"}).status_code, 422)
        self.assertEqual(
            self.post("/users", {"name": "a", "quota": -1}).status_code, 422
        )
        self.assertEqual(
            self.post(
                "/nodes", {"name": "bad", "host": "https://bad/path"}
            ).status_code,
            422,
        )

    def test_node_tokens_isolated_and_rotated(self):
        n = self.node()
        self.assertNotIn(n["token"], self.client.get("/api/nodes").text)
        self.assertEqual(self.client.get("/api/agent/config").status_code, 401)
        h = {"Authorization": "Bearer " + n["token"]}
        isolated = TestClient(app)
        self.assertEqual(isolated.get("/api/users", headers=h).status_code, 401)
        self.assertEqual(
            self.client.get("/api/agent/config", headers=h).status_code, 200
        )
        self.post("/nodes/" + n["id"] + "/rotate-token")
        self.assertEqual(
            self.client.get("/api/agent/config", headers=h).status_code, 401
        )

    def test_usage_is_idempotent_and_monotonic(self):
        u, n = self.user(quota=1000), self.node()
        for up, down in [(100, 200), (100, 200), (90, 180), (200, 400)]:
            self.assertEqual(
                self.heartbeat(n["token"], u["id"], up, down).status_code, 200
            )
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 600)
        self.heartbeat(n["token"], u["id"], 20, 30, "process-2")
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 650)
        self.post("/users/" + u["id"] + "/reset-traffic")
        self.heartbeat(n["token"], u["id"], 30, 50, "process-2")
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 30)

    def test_concurrent_heartbeat_counts_once(self):
        u, n = self.user(), self.node()

        def send(_):
            return self.heartbeat(n["token"], u["id"], 100, 300).status_code

        with ThreadPoolExecutor(max_workers=5) as pool:
            self.assertEqual(list(pool.map(send, range(10))), [200] * 10)
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 400)

    def inbound(self, node, protocol="vless", port=443):
        body = {
            "node_id": node["id"],
            "name": protocol,
            "protocol": protocol,
            "port": port,
            "sni": "www.microsoft.com",
            "cert_file": "/tmp/cert.pem",
            "key_file": "/tmp/key.pem",
        }
        result = self.post("/inbounds", body)
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def test_real_config_and_all_subscription_formats(self):
        u, n = self.user(), self.node()
        for protocol, port in [("vless", 443), ("vmess", 8443), ("trojan", 9443)]:
            self.inbound(n, protocol, port)
        listed = self.client.get("/api/inbounds").json()
        self.assertNotIn("private_key", json.dumps(listed))
        config = self.client.get(
            "/api/agent/config", headers={"Authorization": "Bearer " + n["token"]}
        ).json()
        self.assertEqual(len(config["config"]["inbounds"]), 4)
        for inbound in config["config"]["inbounds"][1:]:
            self.assertEqual(inbound["settings"]["clients"][0]["email"], u["id"])
        url = self.client.get("/api/users/" + u["id"] + "/subscription").json()["url"]
        raw = self.client.get(url + "?format=raw").text
        self.assertIn("vless://", raw)
        self.assertIn("vmess://", raw)
        self.assertIn("trojan://", raw)
        self.assertEqual(base64.b64decode(self.client.get(url).text).decode(), raw)
        clash = self.client.get(url + "?format=clash").json()
        self.assertEqual(len(clash["proxies"]), 3)
        self.assertEqual(self.client.get(url).headers["cache-control"], "no-store")

    def test_expiry_quota_disable_remove_from_config(self):
        u, n = self.user(quota=100), self.node()
        self.inbound(n)

        def clients():
            c = self.client.get(
                "/api/agent/config", headers={"Authorization": "Bearer " + n["token"]}
            ).json()
            return c["config"]["inbounds"][1]["settings"]["clients"]

        self.assertEqual(len(clients()), 1)
        self.heartbeat(n["token"], u["id"], 100, 0)
        self.assertEqual(clients(), [])
        self.assertEqual(self.client.get("/api/users").json()[0]["status"], "limited")
        self.post("/users/" + u["id"] + "/reset-traffic")
        self.assertEqual(len(clients()), 1)
        self.client.put(
            "/api/users/" + u["id"],
            headers=self.headers,
            json={"name": u["name"], "expires": int(time.time()) - 1},
        )
        self.assertEqual(clients(), [])
        self.assertEqual(self.client.get("/api/users").json()[0]["status"], "expired")

    def test_rotate_subscription_and_backup(self):
        u = self.user()
        path = "/api/users/" + u["id"] + "/subscription"
        url = self.client.get(path).json()["url"]
        self.post("/users/" + u["id"] + "/rotate-subscription")
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertNotEqual(url, self.client.get(path).json()["url"])
        result = self.client.get("/api/backup")
        self.assertEqual(result.status_code, 200)
        if postgres_url():
            # PostgreSQL downloads are pg_dump custom-format archives.
            self.assertTrue(result.content.startswith(b"PGDMP"))
        else:
            p = Path(self.tmp.name) / "restore.db"
            p.write_bytes(result.content)
            with sqlite3.connect(p) as backup:
                self.assertEqual(
                    backup.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1
                )

    def test_protocol_credential_rotation_revokes_old_profile(self):
        u, n = self.user(), self.node()
        self.inbound(n)
        url = self.client.get("/api/users/" + u["id"] + "/subscription").json()["url"]
        old_profile = self.client.get(url + "?format=raw").text
        self.post("/users/" + u["id"] + "/rotate-credentials")
        new_url = self.client.get("/api/users/" + u["id"] + "/subscription").json()[
            "url"
        ]
        self.assertEqual(self.client.get(url).status_code, 404)
        new_profile = self.client.get(new_url + "?format=raw").text
        self.assertNotEqual(old_profile, new_profile)
        old_credential = old_profile.split("://")[1].split("@")[0]
        config = self.client.get(
            "/api/agent/config", headers={"Authorization": "Bearer " + n["token"]}
        ).json()
        self.assertNotIn(old_credential, json.dumps(config))

    def test_port_collision_reserved_and_missing_cert(self):
        n = self.node()
        self.inbound(n)
        body = {
            "node_id": n["id"],
            "name": "duplicate",
            "protocol": "vless",
            "port": 443,
            "sni": "example.com",
        }
        self.assertEqual(self.post("/inbounds", body).status_code, 409)
        body["port"] = 10085
        self.assertEqual(self.post("/inbounds", body).status_code, 422)
        body.update(port=8443, protocol="trojan")
        self.assertEqual(self.post("/inbounds", body).status_code, 422)

    def test_stats_parser(self):
        stats = {
            "stat": [
                {"name": "user>>>id>>>traffic>>>uplink", "value": "123"},
                {"name": "user>>>id>>>traffic>>>downlink", "value": 456},
                {"name": "inbound>>>other>>>traffic>>>uplink", "value": 99},
            ]
        }
        self.assertEqual(
            parse_stats(stats), [{"user_id": "id", "up": 123, "down": 456}]
        )

    def test_inbound_edit_preserves_reality_keys_and_can_disable(self):
        self.user()
        n = self.node()
        inbound = self.inbound(n)
        with database() as db:
            before = json.loads(
                db.execute(
                    "SELECT settings FROM inbounds WHERE id=?", (inbound["id"],)
                ).fetchone()[0]
            )
        response = self.client.put(
            "/api/inbounds/" + inbound["id"],
            headers=self.headers,
            json={
                "node_id": n["id"],
                "name": "renamed",
                "protocol": "vless",
                "port": 8443,
                "sni": "www.microsoft.com",
                "enabled": False,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        with database() as db:
            after = json.loads(
                db.execute(
                    "SELECT settings FROM inbounds WHERE id=?", (inbound["id"],)
                ).fetchone()[0]
            )
        self.assertEqual(before["private_key"], after["private_key"])
        self.assertEqual(before["public_key"], after["public_key"])
        self.assertEqual(before["short_id"], after["short_id"])
        config = self.client.get(
            "/api/agent/config", headers={"Authorization": "Bearer " + n["token"]}
        ).json()
        self.assertEqual(len(config["config"]["inbounds"]), 1)
        self.login("operator")
        self.assertEqual(
            self.client.put(
                "/api/inbounds/" + inbound["id"],
                headers=self.headers,
                json={
                    "node_id": n["id"],
                    "name": "x",
                    "protocol": "vless",
                    "port": 8443,
                    "sni": "x.com",
                },
            ).status_code,
            403,
        )

    def test_portal_qr_and_disabled_state_do_not_expose_credentials(self):
        u, n = self.user(quota=1000), self.node()
        self.inbound(n)
        self.heartbeat(n["token"], u["id"], 100, 200)
        links = self.client.get("/api/users/" + u["id"] + "/subscription").json()
        token = links["url"].split("/")[-1]
        guest = TestClient(app)
        page = guest.get(links["portal_url"])
        self.assertEqual(page.status_code, 200)
        result = guest.get("/api/portal/" + token)
        self.assertEqual(result.status_code, 200)
        info = result.json()
        self.assertEqual(
            (info["used"], info["uploaded"], info["downloaded"], info["remaining"]),
            (300, 100, 200, 700),
        )
        self.assertNotIn("credential", info)
        self.assertNotIn("id", info)
        self.assertEqual(len(info["profiles"]), 1)
        for url in (links["qr_url"], info["profiles"][0]["qr_url"]):
            qr = guest.get(url)
            self.assertEqual(qr.status_code, 200)
            self.assertIn("image/svg+xml", qr.headers["content-type"])
            self.assertIn("<svg", qr.text)
            self.assertNotIn("<script", qr.text)
            self.assertEqual(qr.headers["cache-control"], "no-store")
        self.heartbeat(n["token"], u["id"], 1000, 200)
        blocked = guest.get("/api/portal/" + token).json()
        self.assertEqual(blocked["status"], "limited")
        self.assertEqual(blocked["profiles"], [])
        self.assertIsNone(blocked["subscription_url"])
        self.assertEqual(guest.get(links["qr_url"]).status_code, 404)
        self.post("/users/" + u["id"] + "/rotate-subscription")
        self.assertEqual(guest.get(links["portal_url"]).status_code, 404)
        self.assertEqual(guest.get("/api/portal/" + token).status_code, 404)

    def test_agent_replays_persisted_report_after_lost_ack_without_double_count(self):
        from agent.main import NodeAgent
        import httpx

        u, n = self.user(), self.node()
        panel = self.client

        class NodeClient:
            fail = True

            def get(self, path):
                return panel.get(
                    path, headers={"Authorization": "Bearer " + n["token"]}
                )

            def post(self, path, **kwargs):
                result = panel.post(
                    path, headers={"Authorization": "Bearer " + n["token"]}, **kwargs
                )
                if self.fail:
                    self.fail = False
                    raise httpx.ReadTimeout("lost HTTP acknowledgement")
                return result

        client = NodeClient()
        with patch.dict(
            os.environ,
            {
                "DONINO_PANEL_URL": "https://panel.example.com",
                "DONINO_NODE_TOKEN": n["token"],
                "DONINO_NODE_STATE": self.tmp.name + "/node",
            },
        ):
            first = NodeAgent()
            first.client.close()
            first.client = client
            first.usage = [{"user_id": u["id"], "up": 100, "down": 200}]
            with self.assertRaises(httpx.ReadTimeout):
                first.report()
            self.assertEqual(first.journal.count(), 1)
            first.close()
            second = NodeAgent()
            second.client.close()
            second.client = client
            try:
                second.report()
                self.assertEqual(second.journal.count(), 0)
                user = panel.get("/api/users").json()[0]
                self.assertEqual(
                    (user["used"], user["uploaded"], user["downloaded"]),
                    (300, 100, 200),
                )
            finally:
                second.close()


if __name__ == "__main__":
    unittest.main()
