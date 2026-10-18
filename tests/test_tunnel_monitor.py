import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from app import ops, tunnel_monitor as monitor, tunnel_probe
from app.db import (
    database,
    initialize,
    schema_version,
    set_schema_version,
    table_exists,
)
from support import sqlite_only, strip_monitor_schema
from test_tunnel_endpoints import EndpointFixture


class MonitorTest(EndpointFixture):
    def setUp(self):
        super().setUp()
        self.opt = patch.dict(os.environ, {"DONINO_TUNNEL_MONITOR": "1"})
        self.opt.start()
        self.addCleanup(self.opt.stop)
        self.rev = patch(
            "app.tunnel_probe.configuration_revision", return_value="a" * 64
        )
        self.revision = self.rev.start()
        self.addCleanup(self.rev.stop)
        self.instance = "fixture-scheduler"
        self.path = f"/api/tunnels/bindings/{self.bound['id']}/monitor"
        self.check = self.verify().json()
        self.assertEqual(self.publish(self.check).status_code, 200)
        self.assertTrue(monitor.heartbeat(self.instance))

    def enable(self, **changes):
        body = {"check_id": self.check["id"], "confirm_auto_renew": True} | changes
        return self.client.put(self.path, json=body, headers=self.headers)

    def due(self):
        with database() as db:
            db.execute("UPDATE tunnel_monitors SET next_run=1")

    def tick(self, **kwargs):
        from app.tunnel_api import call

        self.due()
        return monitor.run_due(self.instance, call, **kwargs)

    def state_monitor(self):
        return self.client.get(
            f"/api/tunnels/bindings/{self.bound['id']}", headers=self.headers
        ).json()["monitor"]

    def test_explicit_consent_fresh_published_exact_scope_and_live_service_required(
        self,
    ):
        for value in (False, 1, "true", None):
            self.assertEqual(self.enable(confirm_auto_renew=value).status_code, 422)
        for changes in (
            {"interval_seconds": 299},
            {"interval_seconds": 3601},
            {"url": "https://arbitrary.example"},
        ):
            self.assertEqual(self.enable(**changes).status_code, 422)
        monitor.release(self.instance)
        self.assertEqual(self.enable().status_code, 503)
        monitor.heartbeat(self.instance)
        with database() as db:
            db.execute("UPDATE tunnel_checks SET expires=1")
        self.assertEqual(self.enable().status_code, 409)
        self.check = self.verify().json()
        self.assertEqual(self.enable().status_code, 409)
        self.publish(self.check)
        self.assertEqual(self.enable().status_code, 200)
        self.assertNotIn("revision", self.state_monitor())

    def test_renewal_failure_withdrawal_backoff_and_recovery(self):
        self.assertEqual(self.enable().status_code, 200)
        with database() as db:
            db.execute(
                "UPDATE tunnel_endpoints SET expires=?", (int(time.time()) + 10,)
            )
        self.assertTrue(self.tick())
        self.assertEqual(self.state_monitor()["phase"], "healthy")
        self.assertEqual(len(self.subscription()), 2)
        with database() as db:
            self.assertGreater(
                db.execute("SELECT expires FROM tunnel_endpoints").fetchone()[0],
                time.time() + 86000,
            )
        self.run_probe.side_effect = tunnel_probe.ProbeError("probe_connection_closed")
        self.tick()
        state = self.state_monitor()
        self.assertEqual(
            (state["phase"], state["failures"], state["error_code"]),
            ("unhealthy", 1, "probe_connection_closed"),
        )
        self.assertEqual(len(self.subscription()), 1)
        self.assertEqual(self.publish(self.check).status_code, 409)
        self.tick()
        state = self.state_monitor()
        self.assertEqual(state["failures"], 2)
        self.assertGreater(state["next_run"], time.time() + 590)
        self.run_probe.side_effect = None
        self.tick()
        self.assertEqual(
            (self.state_monitor()["phase"], self.state_monitor()["failures"]),
            ("healthy", 0),
        )
        self.assertEqual(len(self.subscription()), 2)

    def test_dead_or_hung_scheduler_filters_exports_before_lease_expiry(self):
        self.enable()
        with database() as db:
            db.execute("UPDATE tunnel_monitor_runtime SET lease_until=1")
        self.assertEqual(len(self.subscription()), 1)
        self.assertFalse(self.state_monitor()["service_ready"])
        monitor.heartbeat(self.instance)
        self.assertEqual(len(self.subscription()), 2)
        with database() as db:
            db.execute("UPDATE tunnel_monitors SET last_success=1")
        self.assertEqual(len(self.subscription()), 1)
        self.tick()
        self.assertEqual(len(self.subscription()), 2)

    def test_device_period_change_fences_grant(self):
        self.enable()
        with database() as db:
            db.execute(
                "UPDATE users SET period_no=period_no+1 WHERE id=?", (self.user["id"],)
            )
        self.assertEqual(len(self.subscription()), 1)
        self.tick()
        self.assertFalse(self.state_monitor()["enabled"])
        self.assertEqual(self.run_probe.call_count, 1)

    def test_device_revocation_filters_exports_and_disables_monitor(self):
        self.enable()
        with database() as db:
            db.execute("UPDATE devices SET enabled=0 WHERE id=?", (self.device,))
        self.assertEqual(len(self.subscription()), 0)
        self.tick()
        self.assertFalse(self.state_monitor()["enabled"])

    def test_source_change_requires_fresh_plan(self):
        self.enable()
        with database() as db:
            db.execute(
                "UPDATE inbounds SET port=9553 WHERE id=?", (self.inbound["id"],)
            )
        self.assertEqual(len(self.subscription()), 1)
        self.tick()
        self.assertFalse(self.state_monitor()["enabled"])

    def test_operator_configuration_change_requires_fresh_consent(self):
        self.enable()
        self.revision.return_value = "b" * 64
        self.assertEqual(len(self.subscription()), 1)
        self.tick()
        self.assertEqual(self.state_monitor()["error_code"], "monitor_scope_changed")
        self.assertFalse(self.state_monitor()["enabled"])

    def test_owner_only_and_manual_disable_fences_late_success(self):
        self.enable()
        self.login("viewer")
        self.assertEqual(self.enable().status_code, 403)
        self.assertEqual(
            self.client.delete(self.path, headers=self.headers).status_code, 403
        )
        self.login()

        def cancel(_):
            self.assertEqual(
                self.client.delete(self.path, headers=self.headers).status_code, 200
            )

        self.run_probe.side_effect = cancel
        self.tick()
        self.assertEqual(len(self.subscription()), 1)
        self.assertFalse(self.state_monitor()["enabled"])

    def test_device_rotation_during_probe_cannot_renew_old_consent(self):
        self.enable()

        def rotate(_):
            with database() as db:
                db.execute(
                    "UPDATE devices SET secret='rotated-fixture-credential' WHERE id=?",
                    (self.device,),
                )

        self.run_probe.side_effect = rotate
        self.tick()
        self.assertEqual(len(self.subscription()), 1)
        self.assertEqual(self.state_monitor()["phase"], "unhealthy")
        self.tick()
        self.assertFalse(self.state_monitor()["enabled"])

    def test_shutdown_before_publication_withdraws_without_renewal(self):
        self.enable()
        self.tick(stopping=lambda: True)
        self.assertEqual(len(self.subscription()), 1)
        self.assertEqual(self.state_monitor()["error_code"], "monitor_stopped")

    def test_local_operator_opt_out_disables_grants_without_later_resurrection(self):
        from app.cli import main

        self.enable()
        with patch("sys.argv", ["donino", "tunnel-monitor-disable"]):
            main()
        monitor.heartbeat(self.instance)
        self.assertEqual(len(self.subscription()), 1)
        self.assertFalse(self.state_monitor()["enabled"])
        self.assertFalse(self.tick())

    def test_role_revocation_withdraws_and_does_not_recover_automatically(self):
        self.enable()
        with database() as db:
            actor = db.execute("SELECT actor FROM tunnel_monitors").fetchone()[0]
            db.execute("UPDATE admins SET role='viewer' WHERE username=?", (actor,))
        self.assertEqual(len(self.subscription()), 1)
        self.tick()
        with database() as db:
            self.assertEqual(
                db.execute("SELECT enabled FROM tunnel_monitors").fetchone()[0], 0
            )

    def test_unpublish_during_io_prevents_late_republication(self):
        self.enable()
        started, done = threading.Event(), threading.Event()
        self.run_probe.side_effect = lambda _: (started.set(), done.wait(10))
        with ThreadPoolExecutor(1) as pool:
            job = pool.submit(self.tick)
            try:
                self.assertTrue(started.wait(10))
                self.assertEqual(
                    len(self.subscription()), 2
                )  # Good lease retained during probe.
                result = self.client.delete(
                    self.path.replace("/monitor", "/publication"), headers=self.headers
                )
                self.assertEqual(result.status_code, 200)
            finally:
                done.set()
            self.assertTrue(job.result(timeout=10))
        self.assertEqual(len(self.subscription()), 1)
        self.assertFalse(self.state_monitor()["enabled"])

    def test_manual_publication_fences_late_failure_without_losing_new_lease(self):
        self.enable()

        def republish(_):
            result = self.publish(self.check)
            self.assertEqual(result.status_code, 200, result.text)
            raise tunnel_probe.ProbeError("probe_failed")

        self.run_probe.side_effect = republish
        self.tick()
        self.assertEqual(len(self.subscription()), 2)
        self.assertFalse(self.state_monitor()["enabled"])

    def test_singleton_and_claim_fences_expired_replaced_run(self):
        self.enable()
        self.assertFalse(monitor.heartbeat("other"))
        self.due()
        first = monitor.claim_due(self.instance)
        self.assertIsNotNone(first)
        self.assertIsNone(monitor.claim_due(self.instance))
        with database() as db:
            db.execute("UPDATE tunnel_monitors SET claim_until=1")
        second = monitor.claim_due(self.instance)
        self.assertNotEqual(first["run_id"], second["run_id"])
        monitor.failed(first, "late_failure")
        with database() as db:
            self.assertEqual(
                db.execute("SELECT run_id FROM tunnel_monitors").fetchone()[0],
                second["run_id"],
            )

    def test_worker_replacement_and_restore_disable_monitor(self):
        self.enable()
        self.run_probe.side_effect = tunnel_probe.ProbeError("probe_failed")
        self.tick()
        self.state["profiles"][0]["host"] = "198.51.100.99"
        self.client.get("/api/tunnels/state", headers=self.headers)
        self.assertFalse(self.state_monitor()["enabled"])
        self.assertEqual(self.state_monitor()["error_code"], "monitor_worker_changed")

    @sqlite_only
    def test_schema13_migration_backup_failure_and_restore(self):
        self.enable()
        snapshot = Path(self.tmp.name) / "monitor-backup"
        ops.backup(snapshot)
        ops.restore(snapshot, replace=True)
        self.assertEqual(self.login().status_code, 200)
        self.assertFalse(self.state_monitor()["enabled"])
        self.assertEqual(len(self.subscription()), 1)
        with database() as db:
            strip_monitor_schema(db)
            set_schema_version(db, 13)
        with patch(
            "app.db.migration_backup", side_effect=OSError("fixture backup failure")
        ):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 13)
            self.assertFalse(table_exists(db, "tunnel_monitors"))
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 14)
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM tunnel_monitors").fetchone()[0], 0
            )

    def test_history_prunes_only_old_unreferenced_receipts(self):
        self.enable()
        with database() as db:
            row = dict(
                db.execute(
                    "SELECT * FROM tunnel_checks WHERE id=?", (self.check["id"],)
                ).fetchone()
            )
            for index in range(1010):
                db.execute(
                    "INSERT INTO tunnel_checks(id,binding_id,source_revision,job_id,device_id,device_revision,inbound_ids,phase,started,expires) VALUES(?,?,?,?,?,?,?,'failed',1,2)",
                    (
                        f"{index:032x}",
                        row["binding_id"],
                        row["source_revision"],
                        row["job_id"],
                        row["device_id"],
                        row["device_revision"],
                        row["inbound_ids"],
                    ),
                )
        self.tick()
        with database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM tunnel_checks").fetchone()[0], 1002
            )
            self.assertIsNotNone(
                db.execute(
                    "SELECT 1 FROM tunnel_checks WHERE id=?", (self.check["id"],)
                ).fetchone()
            )
