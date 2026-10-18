import copy
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.db import (
    database,
    initialize,
    schema_version,
    set_schema_version,
    table_exists,
)
from test_accounts import PanelBase


class BindingTest(PanelBase):
    def setUp(self):
        super().setUp()
        os.environ["DONINO_TUNNEL_BRIDGE"] = "1"
        self.node = self.post(
            "/nodes", {"name": "foreign", "host": "vpn.example.com"}
        ).json()
        self.inbound_args = {
            "node_id": self.node["id"],
            "name": "private-origin",
            "protocol": "trojan",
            "transport": "ws",
            "port": 8443,
            "sni": "private-name.example",
            "cert_file": "/private/origin.pem",
            "key_file": "/private/origin.key",
        }
        result = self.post("/inbounds", self.inbound_args)
        self.assertEqual(result.status_code, 201, result.text)
        self.inbound = result.json()
        self.body = {
            "node_id": self.node["id"],
            "profile_id": "a" * 32,
            "iran": "192.0.2.10",
            "services": [{"inbound_id": self.inbound["id"], "listen_port": 1443}],
            "transports": ["frp-wss", "frp-quic"],
        }
        self.state = {
            "available": True,
            "busy": False,
            "profiles": [
                {
                    "id": "a" * 32,
                    "name": "paired-foreign",
                    "host": "198.51.100.20",
                    "management": "https-v1",
                }
            ],
            "jobs": [],
        }
        self.calls = []
        self.preview_number = 0
        self.preview_hook = None
        self.start_hook = None
        self.mock = patch("app.tunnel_api.call", side_effect=self.controller)
        self.mock.start()

    def tearDown(self):
        self.mock.stop()
        super().tearDown()

    def controller(self, method, route, body=None):
        self.calls.append((method, route, copy.deepcopy(body)))
        if route == "/state":
            return copy.deepcopy(self.state)
        if route == "/preview":
            self.preview_number += 1
            if self.preview_hook:
                self.preview_hook()
            return {
                "id": f"{self.preview_number:032x}",
                "expires_at": time.time() + 3600,
                "summary": {
                    "iran": body["iran"],
                    "foreign": self.state["profiles"][0]["host"],
                    "transports": body["transports"],
                    "services": body["services"],
                    "firewall": {
                        "iran": {"tcp": [1443, 24443], "udp": [24444]},
                        "foreign": {"tcp": [9444], "udp": []},
                    },
                },
            }
        if route == "/start":
            job = {
                "id": "c" * 32,
                "plan_id": body["plan_id"],
                "status": "running",
                "stage": "queued",
                "created": time.time(),
                "updated": time.time(),
            }
            if self.start_hook:
                self.start_hook(job)
            self.state["jobs"] = [job]
            return job
        raise AssertionError("Unexpected controller route")

    def create(self):
        result = self.post("/tunnels/bindings", self.body)
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def launch(self, binding):
        return self.post(
            f"/tunnels/bindings/{binding['id']}/start", {"confirm_replace": True}
        )

    def test_plan_compiles_from_database_and_survives_reinitialization_without_secrets(
        self,
    ):
        result = self.create()
        spec = next(body for _, route, body in self.calls if route == "/preview")
        self.assertEqual(
            spec["services"],
            [
                {
                    "id": result["summary"]["services"][0]["id"],
                    "listen": "0.0.0.0:1443",
                    "target": "127.0.0.1:8443",
                    "protocol": "tcp",
                }
            ],
        )
        self.assertTrue(result["can_start"])
        self.assertEqual(len(result["source_revision"]), 64)
        self.assertNotIn("/private/", json.dumps(result))
        self.assertNotIn("private-name.example", json.dumps(result))
        initialize()
        restored = self.client.get(f"/api/tunnels/bindings/{result['id']}").json()
        self.assertEqual(restored, result)
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT host FROM nodes WHERE id=?", (self.node["id"],)
                ).fetchone()[0],
                "vpn.example.com",
            )
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_changed_inbound_or_deleted_node_cannot_start_a_saved_plan(self):
        for change in ({"port": 9443}, {"sni": "changed.example"}, {"enabled": False}):
            result = self.create()
            changed = self.client.put(
                f"/api/inbounds/{self.inbound['id']}",
                headers=self.headers,
                json={**self.inbound_args, **change},
            )
            self.assertEqual(changed.status_code, 200, changed.text)
            self.assertEqual(self.launch(result).status_code, 409)
            self.assertEqual(
                self.client.get(f"/api/tunnels/bindings/{result['id']}").json()[
                    "phase"
                ],
                "stale",
            )
            self.client.put(
                f"/api/inbounds/{self.inbound['id']}",
                headers=self.headers,
                json=self.inbound_args,
            )
        result = self.create()
        removed = self.client.delete(
            f"/api/nodes/{self.node['id']}", headers=self.headers
        )
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.launch(result).status_code, 409)
        self.assertFalse(any(route == "/start" for _, route, _ in self.calls))

    def test_changes_during_worker_preview_are_recorded_as_stale(self):
        def change():
            # This write would block if the panel kept a DB writer lock over HTTP.
            with database() as db:
                db.execute(
                    "UPDATE inbounds SET port=9443 WHERE id=?", (self.inbound["id"],)
                )

        self.preview_hook = change
        result = self.post("/tunnels/bindings", self.body)
        self.assertEqual(result.status_code, 409, result.text)
        stored = self.client.get("/api/tunnels/bindings").json()[0]
        self.assertEqual(stored["phase"], "stale")
        self.assertIsNotNone(stored["plan_id"])
        self.assertFalse(stored["can_start"])

    def test_expiry_peer_changes_and_raw_start_cannot_bypass_the_binding(self):
        result = self.create()
        self.assertEqual(
            self.post(
                "/tunnels/start",
                {"plan_id": result["plan_id"], "confirm_replace": True},
            ).status_code,
            409,
        )
        with database() as db:
            db.execute(
                "UPDATE tunnel_bindings SET expires=? WHERE id=?",
                (int(time.time()) - 1, result["id"]),
            )
        self.assertEqual(self.launch(result).status_code, 409)
        result = self.create()
        self.state["profiles"][0]["host"] = "203.0.113.20"
        self.assertEqual(self.launch(result).status_code, 409)
        self.assertFalse(any(route == "/start" for _, route, _ in self.calls))

    def test_lost_response_reconciles_by_plan_identity_without_repeating_start(self):
        result = self.create()

        def lost(job):
            self.state["jobs"] = [job]
            raise HTTPException(502, "Lost reply")

        self.start_hook = lost
        self.assertEqual(self.launch(result).status_code, 502)
        pending = self.client.get(f"/api/tunnels/bindings/{result['id']}").json()
        self.assertEqual(pending["phase"], "start_unknown")
        reconciled = self.client.get("/api/tunnels/state").json()["bindings"][0]
        self.assertEqual(reconciled["phase"], "running")
        self.assertEqual(reconciled["job_id"], "c" * 32)
        self.assertEqual(self.launch(result).status_code, 202)
        self.assertEqual(sum(route == "/start" for _, route, _ in self.calls), 1)
        self.state["jobs"][0]["status"] = "succeeded"
        completed = self.client.get("/api/tunnels/state").json()["bindings"][0]
        self.assertEqual(completed["phase"], "succeeded")
        self.assertFalse(completed["application_verified"])
        self.assertFalse(completed["endpoint_published"])

    def test_concurrent_start_is_claimed_once_before_worker_io(self):
        result = self.create()
        entered, release = threading.Event(), threading.Event()

        def hold(job):
            entered.set()
            if not release.wait(5):
                raise AssertionError("Concurrent test timed out")

        self.start_hook = hold
        with ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(self.launch, result)
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.launch(result).status_code, 409)
            finally:
                release.set()
            response = first.result(timeout=5)
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(sum(route == "/start" for _, route, _ in self.calls), 1)

    def test_worker_cannot_substitute_targets_or_attach_an_unrelated_job(self):
        original = self.controller

        def wrong_target(method, route, body=None):
            value = copy.deepcopy(original(method, route, body))
            if route == "/preview":
                value["summary"]["services"][0]["target"] = "127.0.0.1:9999"
            return value

        with patch("app.tunnel_api.call", side_effect=wrong_target):
            response = self.post("/tunnels/bindings", self.body)
        self.assertEqual(response.status_code, 502, response.text)
        self.assertEqual(
            self.client.get("/api/tunnels/bindings").json()[0]["phase"],
            "preview_unknown",
        )
        result = self.create()

        def wrong_job(method, route, body=None):
            value = copy.deepcopy(original(method, route, body))
            if route == "/start":
                value["plan_id"] = "f" * 32
            return value

        with patch("app.tunnel_api.call", side_effect=wrong_job):
            response = self.launch(result)
        self.assertEqual(response.status_code, 502, response.text)
        unknown = self.client.get(f"/api/tunnels/bindings/{result['id']}").json()
        self.assertEqual(unknown["phase"], "start_unknown")
        self.assertIsNone(unknown["job_id"])

    def test_validation_cross_node_selection_roles_and_explicit_confirmation(self):
        other = self.post("/nodes", {"name": "other", "host": "other.example"}).json()
        for change in (
            {"node_id": other["id"]},
            {"services": self.body["services"] * 2},
            {"services": [{**self.body["services"][0], "target_port": 9999}]},
            {"transports": ["paqet"]},
        ):
            response = self.post("/tunnels/bindings", {**self.body, **change})
            self.assertIn(response.status_code, (409, 422), response.text)
        result = self.create()
        for confirmation in (False, 1):
            self.assertEqual(
                self.post(
                    f"/tunnels/bindings/{result['id']}/start",
                    {"confirm_replace": confirmation},
                ).status_code,
                422,
            )
        self.login("operator")
        self.assertEqual(self.client.get("/api/tunnels/bindings").status_code, 403)
        self.assertEqual(self.post("/tunnels/bindings", self.body).status_code, 403)
        self.assertEqual(self.launch(result).status_code, 403)

    def test_v10_migration_preserves_nodes_and_backs_up_before_ddl(self):
        with database() as db:
            db.execute("DROP TABLE tunnel_bindings")
            set_schema_version(db, 10)
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 11)
            self.assertTrue(table_exists(db, "tunnel_bindings"))
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0], 1
            )
        backups = list(Path(self.tmp.name).glob("*.pre-v11-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_migration_backup_failure_leaves_v10_intact(self):
        with database() as db:
            db.execute("DROP TABLE tunnel_bindings")
            set_schema_version(db, 10)
        with patch("app.db.migration_backup", side_effect=OSError("Disk full")):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 10)
            self.assertFalse(table_exists(db, "tunnel_bindings"))

    def test_restore_refuses_an_otherwise_empty_database_with_binding_history(self):
        from app.storage import require_empty

        result = self.create()
        with database() as db:
            for table in ("sessions", "admins", "inbounds", "nodes", "audit"):
                db.execute(f"DELETE FROM {table}")
        with self.assertRaisesRegex(ValueError, "empty destination"):
            require_empty()
        with database() as db:
            self.assertEqual(
                db.execute("SELECT id FROM tunnel_bindings").fetchone()[0], result["id"]
            )
