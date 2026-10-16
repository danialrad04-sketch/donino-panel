from fastapi.testclient import TestClient

from test_accounts import PanelBase
from app.db import database
from app.main import app
from agent.journal import UsageJournal


class PeriodAccountingTest(PanelBase):
    def fixture(self):
        user = self.post("/users", {"name": "period-aware", "quota": 1000}).json()
        node = self.post("/nodes", {"name": "n", "host": "vpn.example.com"}).json()
        return user, node, {"Authorization": "Bearer " + node["token"]}

    def report(self, auth, uid, period, up, epoch="old-process"):
        return self.client.post(
            "/api/agent/heartbeat",
            headers=auth,
            json={
                "epoch": epoch,
                "usage": [{"user_id": uid, "up": up, "down": 0, "period_no": period}],
            },
        )

    def test_delayed_old_report_after_reset_never_charges_current_period(self):
        user, node, auth = self.fixture()
        uid = user["id"]
        self.assertEqual(self.report(auth, uid, 0, 300).status_code, 200)
        before = self.client.get("/api/agent/config", headers=auth).json()
        self.post(f"/users/{uid}/reset-traffic")
        after = self.client.get("/api/agent/config", headers=auth).json()
        self.assertNotEqual(before["revision"], after["revision"])
        self.assertEqual(after["periods"][uid], 1)
        # A new process reports first; then an old, previously unacknowledged batch arrives.
        self.assertEqual(
            self.report(auth, uid, 1, 50, epoch="new-process").status_code, 200
        )
        self.assertEqual(self.report(auth, uid, 0, 450).status_code, 200)
        self.assertEqual(self.report(auth, uid, 0, 450).status_code, 200)
        current = self.client.get("/api/users").json()[0]
        self.assertEqual(current["used"], 50)
        history = self.client.get(f"/api/users/{uid}/periods").json()
        self.assertEqual(
            [(p["period_no"], p["uploaded"]) for p in history], [(1, 50), (0, 450)]
        )

    def test_epoch_cannot_relabel_old_cumulative_bytes(self):
        user, _, auth = self.fixture()
        uid = user["id"]
        self.assertEqual(self.report(auth, uid, 0, 100).status_code, 200)
        self.post(f"/users/{uid}/reset-traffic")
        self.assertEqual(self.report(auth, uid, 1, 150).status_code, 409)
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 0)
        self.assertEqual(
            self.report(auth, uid, 50, 150, epoch="invented-period").status_code, 409
        )
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM counters WHERE epoch='invented-period'"
                ).fetchone()[0],
                0,
            )

    def test_node_assignments_filter_configs_and_subscriptions_atomically(self):
        user, first, auth = self.fixture()
        second = self.post(
            "/nodes", {"name": "second", "host": "second.example.com"}
        ).json()
        for node in (first, second):
            self.assertEqual(
                self.post(
                    "/inbounds",
                    {
                        "node_id": node["id"],
                        "name": node["id"],
                        "protocol": "vless",
                        "port": 443,
                        "sni": "www.microsoft.com",
                    },
                ).status_code,
                201,
            )
        endpoint = f"/api/users/{user['id']}/nodes"
        selected = self.client.put(
            endpoint,
            headers=self.headers,
            json={"mode": "selected", "node_ids": [second["id"]]},
        )
        self.assertEqual(selected.status_code, 200)
        first_config = self.client.get("/api/agent/config", headers=auth).json()
        self.assertNotIn(user["id"], first_config["periods"])
        info = self.client.get(f"/api/users/{user['id']}/subscription").json()
        info = self.client.get(info["url"] + "?format=raw").text
        self.assertNotIn("vpn.example.com", str(info))
        self.assertIn("second.example.com", str(info))
        bad = self.client.put(
            endpoint,
            headers=self.headers,
            json={"mode": "selected", "node_ids": ["missing"]},
        )
        self.assertEqual(bad.status_code, 404)
        self.assertEqual(self.client.get(endpoint).json()["node_ids"], [second["id"]])
        viewer = TestClient(app)
        self.login("viewer", client=viewer)
        self.assertEqual(
            viewer.put(
                endpoint, headers=self.headers, json={"mode": "all"}
            ).status_code,
            403,
        )

    def test_journal_keeps_generation_through_restart_and_refuses_relabel(self):
        path = self.tmp.name + "/journal.db"
        sample = {"user_id": "device", "up": 90, "down": 10, "period_no": 7}
        UsageJournal(path).record("process", [sample])
        journal = UsageJournal(path)
        self.assertEqual(journal.pending(), ("process", [sample]))
        with self.assertRaises(ValueError):
            journal.record("process", [{**sample, "period_no": 8}])
        self.assertEqual(journal.pending(), ("process", [sample]))
