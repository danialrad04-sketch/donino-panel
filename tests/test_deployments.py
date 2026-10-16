from test_accounts import PanelBase
from app.db import database, initialize


class DeploymentTest(PanelBase):
    def test_jobs_survive_restart_supersede_and_only_matching_ack_applies(self):
        user = self.post("/users", {"name": "job-user"}).json()
        node = self.post("/nodes", {"name": "jobs", "host": "vpn.example.com"}).json()
        auth = {"Authorization": "Bearer " + node["token"]}
        first = self.client.get("/api/agent/config", headers=auth).json()
        initialize()
        self.assertEqual(
            self.client.get("/api/agent/config", headers=auth).json()["job_id"],
            first["job_id"],
        )
        self.post(f"/users/{user['id']}/reset-traffic")
        second = self.client.get("/api/agent/config", headers=auth).json()
        self.assertNotEqual(first["job_id"], second["job_id"])

        def send(job, revision, **extra):
            return self.client.post(
                "/api/agent/heartbeat",
                headers=auth,
                json={
                    "epoch": "process",
                    "job_id": job,
                    "applied_revision": revision,
                    "core_running": True,
                    **extra,
                },
            )

        send(first["job_id"], first["revision"])
        send(second["job_id"], first["revision"])
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM deployments WHERE id=?", (first["job_id"],)
                ).fetchone()[0],
                "superseded",
            )
            self.assertEqual(
                db.execute(
                    "SELECT state FROM deployments WHERE id=?", (second["job_id"],)
                ).fetchone()[0],
                "pending",
            )
        send(
            second["job_id"],
            first["revision"],
            error="validation failed",
            rejected_revision=second["revision"],
        )
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM deployments WHERE id=?", (second["job_id"],)
                ).fetchone()[0],
                "failed",
            )
        send(second["job_id"], second["revision"])
        send(second["job_id"], second["revision"], error="Node agent stopping")
        listing = self.client.get("/api/deployments").json()
        current = next(row for row in listing if row["id"] == second["job_id"])
        self.assertEqual(current["state"], "applied")
        self.assertNotIn("payload", current)

    def test_node_cannot_acknowledge_another_nodes_job(self):
        first = self.post("/nodes", {"name": "first", "host": "one.example.com"}).json()
        second = self.post(
            "/nodes", {"name": "second", "host": "two.example.com"}
        ).json()
        desired = self.client.get(
            "/api/agent/config", headers={"Authorization": "Bearer " + first["token"]}
        ).json()
        self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": "Bearer " + second["token"]},
            json={
                "epoch": "e",
                "job_id": desired["job_id"],
                "applied_revision": desired["revision"],
                "core_running": True,
            },
        )
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM deployments WHERE id=?", (desired["job_id"],)
                ).fetchone()[0],
                "pending",
            )
