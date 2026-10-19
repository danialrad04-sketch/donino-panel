import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch

from app import ops
from app.db import database, initialize, schema_version, set_schema_version
from app.node_identity import public_material, verify_desired
from app.secrets import unseal
from agent.wireguard import WireGuardAgent
from support import sqlite_only, strip_wireguard_schema
from test_accounts import PanelBase


class WireGuardFixture(PanelBase):
    def setUp(self):
        super().setUp()
        self.node = self.post(
            "/nodes", {"name": "wg-node", "host": "vpn.example.com"}
        ).json()
        self.user = self.post("/users", {"name": "wg-user"}).json()
        body = {"node_id": self.node["id"], "name": "WG", "host": "vpn.example.com"}
        response = self.post("/wireguard/endpoints", body)
        self.assertEqual(response.status_code, 201, response.text)
        self.endpoint = response.json()
        response = self.post(
            f"/wireguard/endpoints/{self.endpoint['id']}/peers",
            {"device_id": self.user["id"]},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.peer = response.json()
        self.client.put(
            f"/api/wireguard/endpoints/{self.endpoint['id']}",
            headers=self.headers,
            json={"enabled": True},
        )
        self.node_headers = {"Authorization": "Bearer " + self.node["token"]}

    def desired(self, instance=None):
        return self.client.get(
            "/api/agent/wireguard/config",
            params={"instance": instance or str(uuid.uuid4())},
            headers=self.node_headers,
        ).json()

    def profile(self):
        return self.client.get(
            f"/api/wireguard/peers/{self.peer['id']}/profile", headers=self.headers
        )


class WireGuardAPITest(WireGuardFixture):
    def test_delete_requires_disabled_state_and_preserves_accounting(self):
        path = "/api/wireguard/peers/" + self.peer["id"]
        self.assertEqual(
            self.client.delete(path, headers=self.headers).status_code, 409
        )
        self.client.put(path, headers=self.headers, json={"enabled": False})
        self.assertEqual(
            self.client.delete(path, headers=self.headers).status_code, 204
        )
        endpoint = "/api/wireguard/endpoints/" + self.endpoint["id"]
        self.assertEqual(
            self.client.delete(endpoint, headers=self.headers).status_code, 409
        )
        self.client.put(endpoint, headers=self.headers, json={"enabled": False})
        self.assertEqual(
            self.client.delete(endpoint, headers=self.headers).status_code, 204
        )
        with database() as db:
            self.assertIsNotNone(
                db.execute(
                    "SELECT id FROM devices WHERE id=?", (self.user["id"],)
                ).fetchone()
            )
            self.assertFalse(list(db.execute("SELECT * FROM wg_peers")))

    def test_independent_encrypted_keys_scoped_profile_and_signed_config(self):
        response = self.profile()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("Address = 10.66.0.2/32", response.text)
        with database() as db:
            peer = db.execute("SELECT * FROM wg_peers").fetchone()
            self.assertTrue(peer["private_key"].startswith("fernet:"))
            self.assertNotIn(unseal(peer["private_key"]), str(self.peer))
            self.assertNotEqual(
                unseal(peer["private_key"]),
                db.execute("SELECT secret FROM devices").fetchone()[0],
            )
        envelope = self.desired()
        body = verify_desired(
            envelope, public_material()["config_verify_key"], self.node["id"]
        )
        server = body["interfaces"][0]
        self.assertEqual(server["peers"][0]["public_key"], self.peer["public_key"])
        self.assertNotIn("private_key", server["peers"][0])
        self.assertNotIn("wg_peers", str(self.client.get("/api/inbounds").json()))

    def test_owner_permissions_input_guard_and_allocator(self):
        self.login("viewer")
        self.assertEqual(self.profile().status_code, 403)
        self.login()
        for pool in ("127.0.0.0/24", "192.0.2.0/24", "10.66.0.1/24", "10.0.0.0/8"):
            result = self.post(
                "/wireguard/endpoints",
                {
                    "node_id": self.node["id"],
                    "name": "bad",
                    "host": "vpn.example",
                    "pool": pool,
                },
            )
            self.assertEqual(result.status_code, 422)
        duplicate = self.post(
            "/wireguard/endpoints",
            {
                "node_id": self.node["id"],
                "name": "overlap",
                "host": "vpn.example",
                "port": 51821,
                "pool": "10.66.0.0/25",
            },
        )
        self.assertEqual(duplicate.status_code, 409)
        second = self.post(
            f"/users/{self.user['id']}/devices", {"name": "second"}
        ).json()
        result = self.post(
            f"/wireguard/endpoints/{self.endpoint['id']}/peers",
            {"device_id": second["id"]},
        )
        self.assertEqual(result.status_code, 201, result.text)
        self.assertEqual(result.json()["address"], "10.66.0.3")

    def test_rotation_revocation_period_and_lease_quota_guards(self):
        old = self.peer["public_key"]
        self.post(f"/devices/{self.user['id']}/rotate-secret")
        new = self.desired()["interfaces"][0]["peers"][0]
        self.assertNotEqual(old, new["public_key"])
        self.assertEqual(new["address"], self.peer["address"])
        with database() as db:
            db.execute("UPDATE users SET expires=1 WHERE id=?", (self.user["id"],))
        self.assertEqual(self.profile().status_code, 409)
        self.assertEqual(self.desired()["interfaces"][0]["peers"], [])
        with database() as db:
            db.execute(
                "UPDATE users SET expires=NULL,quota_mode='lease' WHERE id=?",
                (self.user["id"],),
            )
        self.assertEqual(self.profile().status_code, 409)
        self.assertEqual(self.desired()["interfaces"][0]["peers"], [])

    def test_usage_duplicate_old_period_and_assignment(self):
        epoch, instance = str(uuid.uuid4()), str(uuid.uuid4())
        payload = {
            "epoch": epoch,
            "instance": instance,
            "usage": [
                {"user_id": self.user["id"], "period_no": 0, "up": 123, "down": 456}
            ],
        }
        for _ in range(2):
            result = self.client.post(
                "/api/agent/wireguard/heartbeat",
                headers=self.node_headers,
                json=payload,
            )
            self.assertEqual(result.status_code, 200, result.text)
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT used FROM users WHERE id=?", (self.user["id"],)
                ).fetchone()[0],
                579,
            )
            db.execute(
                "UPDATE users SET node_mode='selected' WHERE id=?", (self.user["id"],)
            )
        self.assertEqual(self.desired()["interfaces"][0]["peers"], [])
        self.assertEqual(self.profile().status_code, 409)

    @sqlite_only
    def test_upgrade_backup_failure_restore_disables_endpoint(self):
        archive = Path(self.tmp.name) / "wg-backup"
        ops.backup(archive)
        ops.restore(archive, replace=True)
        self.login()
        self.assertEqual(self.profile().status_code, 409)
        with database() as db:
            strip_wireguard_schema(db)
            set_schema_version(db, 14)
        with patch("app.db.migration_backup", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 14)
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 15)


class FakeKernel:
    def __init__(self):
        self.links = {}
        self.fail = False

    def exists(self, name):
        return name in self.links

    def public_key(self, name):
        return self.links[name]["public_key"]

    def check(self, interface, owned):
        if self.exists(interface["name"]):
            raise ValueError("unmanaged link")

    def create(self, interface, deadline):
        self.links[interface["name"]] = {
            "public_key": interface["public_key"],
            "counters": {p["public_key"]: (0, 0) for p in interface["peers"]},
        }
        if self.fail:
            raise RuntimeError("partial failure")

    def counters(self, name):
        return dict(self.links[name]["counters"])

    def remove_peer(self, name, public):
        self.links[name]["counters"].pop(public, None)

    def down(self, name):
        pass

    def delete(self, name):
        del self.links[name]


class WireGuardAgentTest(WireGuardFixture):
    def setUp(self):
        super().setUp()
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_PANEL_URL": "https://panel.example",
                "DONINO_WG_STATE": self.tmp.name + "/wg",
            },
        )
        self.env.start()
        self.kernel = FakeKernel()
        client = self.client
        headers = self.node_headers

        class LocalPanel:
            def get(self, path, **kwargs):
                return client.get(path, headers=headers, **kwargs)

            def post(self, path, **kwargs):
                return client.post(path, headers=headers, **kwargs)

            def close(self):
                pass

        self.identity = {
            "node_id": self.node["id"],
            "config_verify_key": public_material()["config_verify_key"],
            "expires": time.time() + 30 * 86400,
        }
        self.agent = WireGuardAgent(
            client=LocalPanel(), identity=self.identity, kernel=self.kernel
        )

    def tearDown(self):
        try:
            self.agent.close()
        finally:
            self.env.stop()
            super().tearDown()

    def test_counters_replay_restart_expiry_and_local_quota(self):
        self.agent.tick()
        name = next(iter(self.kernel.links))
        self.kernel.links[name]["counters"][self.peer["public_key"]] = (200, 300)
        self.agent.tick()
        self.agent.tick()
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT used FROM users WHERE id=?", (self.user["id"],)
                ).fetchone()[0],
                500,
            )
            db.execute("UPDATE users SET quota=600 WHERE id=?", (self.user["id"],))
        self.agent.tick()
        self.kernel.links[name]["counters"][self.peer["public_key"]] = (300, 400)
        self.agent.enforce()
        self.assertNotIn(self.peer["public_key"], self.kernel.links[name]["counters"])
        self.agent.tick()
        self.assertEqual(self.kernel.links[name]["counters"], {})

    def test_signed_deadline_and_invalid_signature_cannot_extend_service(self):
        self.agent.tick()
        self.agent.deadline = time.monotonic() - 1
        self.agent.enforce()
        self.assertFalse(self.kernel.links)
        original = self.agent.client.get

        def tamper(*args, **kwargs):
            import httpx

            value = original(*args, **kwargs).json()
            value["interfaces"][0]["port"] += 1
            return httpx.Response(
                200, json=value, request=httpx.Request("GET", "https://panel.example")
            )

        self.agent.client.get = tamper
        with self.assertRaises(ValueError):
            self.agent.tick()
        self.assertFalse(self.kernel.links)

    def test_partial_apply_removes_only_owned_links(self):
        self.kernel.fail = True
        self.kernel.links["foreign"] = {"public_key": "not-owned", "counters": {}}
        with self.assertRaises(RuntimeError):
            self.agent.tick()
        self.assertEqual(set(self.kernel.links), {"foreign"})

    def test_offline_cleanup_does_not_require_valid_identity_and_journals_bytes(self):
        self.agent.tick()
        name = next(iter(self.kernel.links))
        self.kernel.links[name]["counters"][self.peer["public_key"]] = (123, 456)
        # Simulate process death with surviving kernel link and persisted state.
        self.agent.stop.set()
        self.agent.watchdog.join(timeout=2)
        self.agent.lock.close()
        WireGuardAgent.cleanup(self.agent.directory, kernel=self.kernel)
        self.assertFalse(self.kernel.links)
        self.assertIsNotNone(self.agent.journal.pending())
        # Let fixture teardown use the already-cleaned state.
        self.agent.interfaces, self.agent.owned = [], {}

    def test_offline_cleanup_refuses_foreign_link_and_live_agent(self):
        self.agent.tick()
        with self.assertRaises(BlockingIOError):
            WireGuardAgent.cleanup(self.agent.directory, kernel=self.kernel)
        name = next(iter(self.kernel.links))
        public = self.kernel.links[name]["public_key"]
        self.agent.stop.set()
        self.agent.watchdog.join(timeout=2)
        self.agent.lock.close()
        self.kernel.links[name]["public_key"] = "foreign"
        try:
            with self.assertRaises(ValueError):
                WireGuardAgent.cleanup(self.agent.directory, kernel=self.kernel)
            self.assertIn(name, self.kernel.links)
        finally:
            self.kernel.links[name]["public_key"] = public

    def test_counter_reset_preserves_observed_usage(self):
        self.agent.tick()
        name = next(iter(self.kernel.links))
        self.kernel.links[name]["counters"][self.peer["public_key"]] = (100, 200)
        self.agent.report()
        self.kernel.links[name]["counters"][self.peer["public_key"]] = (10, 20)
        self.agent.report()
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT used FROM users WHERE id=?", (self.user["id"],)
                ).fetchone()[0],
                330,
            )
