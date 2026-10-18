import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from app import ops, tunnel_probe
from app.db import (
    database,
    initialize,
    schema_version,
    set_schema_version,
    table_exists,
)
import test_tunnel_bindings as fixtures


class EndpointTest(fixtures.BindingFixture):
    def setUp(self):
        super().setUp()
        self.available = patch("app.tunnel_probe.available", return_value=True)
        self.availability = self.available.start()
        self.probe = patch("app.tunnel_probe.run", return_value={})
        self.run_probe = self.probe.start()
        self.user = self.post("/users", {"name": "probe-user"}).json()
        self.device = self.user["id"]
        with database() as db:
            self.token = db.execute(
                "SELECT token FROM users WHERE id=?", (self.user["id"],)
            ).fetchone()[0]
        self.bound = self.create()
        self.launch(self.bound)
        self.state["jobs"][0]["status"] = "succeeded"

    def tearDown(self):
        self.probe.stop()
        self.available.stop()
        super().tearDown()

    def verify(self):
        return self.post(
            f"/tunnels/bindings/{self.bound['id']}/verify",
            {"device_id": self.device, "inbound_ids": [self.inbound["id"]]},
        )

    def publish(self, check):
        return self.post(
            f"/tunnels/bindings/{self.bound['id']}/publication",
            {"check_id": check["id"], "confirm_publish": True},
        )

    def subscription(self):
        return self.client.get(f"/sub/{self.token}?format=clash").json()["proxies"]

    def test_success_publishes_only_a_guarded_additive_endpoint_and_unpublish_is_idempotent(
        self,
    ):
        result = self.verify()
        self.assertEqual(result.status_code, 201, result.text)
        check = result.json()
        self.assertEqual(check["phase"], "succeeded")
        proxy = self.run_probe.call_args.args[0][0]
        self.assertEqual(
            (proxy["server"], proxy["port"], proxy["sni"]),
            ("192.0.2.10", 1443, "private-name.example"),
        )
        self.assertNotIn(proxy["password"], result.text)
        self.assertNotIn("device_revision", result.text)
        self.assertEqual(len(self.subscription()), 1)
        published = self.publish(check)
        self.assertEqual(published.status_code, 200, published.text)
        self.assertTrue(published.json()["endpoint_published"])
        entries = self.subscription()
        self.assertEqual(len(entries), 2)
        self.assertEqual(
            (entries[0]["server"], entries[0]["port"]), ("vpn.example.com", 8443)
        )
        self.assertEqual(
            (entries[1]["server"], entries[1]["port"]), ("192.0.2.10", 1443)
        )
        self.assertEqual(entries[0]["sni"], entries[1]["sni"])
        self.assertEqual(entries[0]["password"], entries[1]["password"])
        self.assertNotEqual(entries[0]["name"], entries[1]["name"])
        raw = self.client.get(f"/sub/{self.token}?format=raw").text
        self.assertIn("@192.0.2.10:1443?", raw)
        initialize()
        self.assertEqual(len(self.subscription()), 2)
        for _ in range(2):
            result = self.client.delete(
                f"/api/tunnels/bindings/{self.bound['id']}/publication",
                headers=self.headers,
            )
            self.assertEqual(result.status_code, 200)
        self.assertEqual(len(self.subscription()), 1)

    def test_origin_guard_filters_future_exports_and_publication_without_rewriting_node(
        self,
    ):
        check = self.verify().json()
        self.assertEqual(self.publish(check).status_code, 200)
        with database() as db:
            db.execute(
                "UPDATE inbounds SET port=9553 WHERE id=?", (self.inbound["id"],)
            )
        self.assertEqual(len(self.subscription()), 1)
        self.assertEqual(self.publish(check).status_code, 409)
        metadata = self.client.get(f"/api/tunnels/bindings/{self.bound['id']}").json()
        self.assertFalse(metadata["application_verified"])
        self.assertFalse(metadata["endpoint_published"])
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT host FROM nodes WHERE id=?", (self.node["id"],)
                ).fetchone()[0],
                "vpn.example.com",
            )

    def test_stale_receipt_expired_lease_and_revoked_probe_device_cannot_publish(self):
        check = self.verify().json()
        with database() as db:
            db.execute("UPDATE tunnel_checks SET expires=1 WHERE id=?", (check["id"],))
        self.assertEqual(self.publish(check).status_code, 409)
        check = self.verify().json()
        self.publish(check)
        with database() as db:
            db.execute("UPDATE tunnel_endpoints SET expires=1")
        self.assertEqual(len(self.subscription()), 1)
        with database() as db:
            db.execute("UPDATE devices SET enabled=0 WHERE id=?", (self.device,))
        self.assertEqual(self.publish(check).status_code, 409)
        self.assertEqual(self.verify().status_code, 409)

    def test_failed_retest_withdraws_previous_proof_and_never_exposes_diagnostics(self):
        first = self.verify().json()
        self.publish(first)
        self.run_probe.side_effect = tunnel_probe.ProbeError("probe_transfer_failed")
        failed = self.verify()
        self.assertEqual(failed.json()["phase"], "failed")
        self.assertEqual(failed.json()["error_code"], "probe_transfer_failed")
        self.assertEqual(len(self.subscription()), 1)
        self.assertEqual(self.publish(first).status_code, 409)
        self.assertFalse(
            self.publish(failed.json()).json().get("endpoint_published", False)
        )

    def test_replacement_manual_or_bound_invalidates_proofs_before_worker_io(self):
        for bound_start in (False, True):
            check = self.verify().json()
            self.assertEqual(self.publish(check).status_code, 200)

            def inspect(job):
                self.assertEqual(len(self.subscription()), 1)
                if job["plan_id"] != self.bound["plan_id"]:
                    job["id"] = "d" * 32

            self.start_hook = inspect
            if bound_start:
                self.state["jobs"][0]["status"] = "succeeded"
                new = self.create()
                result = self.launch(new)
            else:
                result = self.post(
                    "/tunnels/start", {"plan_id": "f" * 32, "confirm_replace": True}
                )
            self.assertEqual(result.status_code, 202, result.text)
            self.assertEqual(len(self.subscription()), 1)
            self.assertEqual(self.publish(check).status_code, 409)
            # Restore the fixture's original successful install for next case.
            self.state["jobs"] = [
                {
                    "id": "c" * 32,
                    "plan_id": self.bound["plan_id"],
                    "status": "succeeded",
                    "stage": "done",
                    "created": time.time(),
                    "updated": time.time(),
                }
            ]

    def test_external_worker_replacement_and_lost_history_invalidate_publication_on_observation(
        self,
    ):
        for change in ("peer", "later_job", "missing_job"):
            original = copy.deepcopy(self.state)
            check = self.verify().json()
            self.publish(check)
            if change == "peer":
                self.state["profiles"][0]["host"] = "198.51.100.30"
            elif change == "later_job":
                self.state["jobs"].append(
                    {
                        **self.state["jobs"][0],
                        "id": "e" * 32,
                        "plan_id": "f" * 32,
                        "created": time.time() + 1,
                    }
                )
            else:
                self.state["jobs"] = []
            self.assertEqual(self.client.get("/api/tunnels/state").status_code, 200)
            self.assertEqual(len(self.subscription()), 1)
            self.assertEqual(self.publish(check).status_code, 409)
            self.state = original

    def test_probe_and_relay_exports_preserve_node_assignments(self):
        other = self.post("/nodes", {"name": "other", "host": "other.example"}).json()
        with database() as db:
            db.execute(
                "UPDATE users SET node_mode='selected' WHERE id=?", (self.user["id"],)
            )
            db.execute(
                "INSERT INTO user_nodes(user_id,node_id) VALUES(?,?)",
                (self.user["id"], other["id"]),
            )
        self.assertEqual(self.verify().status_code, 409)
        self.assertEqual(self.subscription(), [])
        with database() as db:
            db.execute(
                "INSERT INTO user_nodes(user_id,node_id) VALUES(?,?)",
                (self.user["id"], self.node["id"]),
            )
        check = self.verify().json()
        self.assertEqual(self.publish(check).status_code, 200)
        self.assertEqual(len(self.subscription()), 2)
        with database() as db:
            db.execute(
                "DELETE FROM user_nodes WHERE user_id=? AND node_id=?",
                (self.user["id"], self.node["id"]),
            )
        self.assertEqual(self.subscription(), [])
        self.assertEqual(self.publish(check).status_code, 409)

    def test_concurrent_probe_claim_and_origin_device_changes_during_io(self):
        entered, release = threading.Event(), threading.Event()

        def blocking(proxies):
            entered.set()
            self.assertTrue(release.wait(5))

        self.run_probe.side_effect = blocking
        with ThreadPoolExecutor(2) as pool:
            future = pool.submit(self.verify)
            self.assertTrue(entered.wait(5))
            self.assertEqual(self.verify().status_code, 409)
            # No writer lock is held over the real-client transfer.
            with database() as db:
                db.execute(
                    "UPDATE devices SET secret=? WHERE id=?", ("changed", self.device)
                )
            release.set()
            check = future.result().json()
        self.assertEqual(check["phase"], "failed")
        self.assertEqual(check["error_code"], "probe_origin_changed")
        self.assertEqual(self.publish(check).status_code, 409)

    def test_owner_strict_confirmation_and_server_config_only(self):
        check = self.verify().json()
        for extra in (
            {"url": "https://evil.example"},
            {"binary": "/bin/sh"},
            {"credential": "private"},
        ):
            r = self.post(
                f"/tunnels/bindings/{self.bound['id']}/verify",
                {
                    "device_id": self.device,
                    "inbound_ids": [self.inbound["id"]],
                    **extra,
                },
            )
            self.assertEqual(r.status_code, 422)
        for confirmation in (False, 1, "true"):
            r = self.post(
                f"/tunnels/bindings/{self.bound['id']}/publication",
                {"check_id": check["id"], "confirm_publish": confirmation},
            )
            self.assertEqual(r.status_code, 422)
        self.availability.return_value = False
        self.assertEqual(self.verify().status_code, 503)
        self.login("operator")
        self.assertEqual(self.verify().status_code, 403)
        self.assertEqual(self.publish(check).status_code, 403)
        self.assertEqual(
            self.client.delete(
                f"/api/tunnels/bindings/{self.bound['id']}/publication",
                headers=self.headers,
            ).status_code,
            403,
        )

    def test_restoration_invalidates_leases_but_keeps_acceptance_history(self):
        check = self.verify().json()
        self.publish(check)
        backup = Path(self.tmp.name) / "acceptance.backup"
        ops.backup(backup)
        ops.restore(backup, replace=True)
        with database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM tunnel_endpoints").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute(
                    "SELECT phase FROM tunnel_checks WHERE id=?", (check["id"],)
                ).fetchone()[0],
                "invalidated",
            )

    def test_schema11_upgrade_backup_and_failure_before_ddl(self):
        # Empty acceptance tables are the only difference from schema 11.
        with database() as db:
            db.execute("DROP TABLE tunnel_endpoints")
            db.execute("DROP TABLE tunnel_checks")
            set_schema_version(db, 11)
        with patch("app.db.migration_backup", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 11)
            self.assertFalse(table_exists(db, "tunnel_checks"))
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 12)
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM tunnel_bindings").fetchone()[0], 1
            )
        self.assertTrue(list(Path(self.tmp.name).glob("*.pre-v12-*")))
