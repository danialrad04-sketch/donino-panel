import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from test_accounts import PanelBase
from agent.identity import certificate_request
from agent.journal import UsageJournal
from app.db import database


class BudgetLeaseTest(PanelBase):
    def setUp(self):
        super().setUp()
        os.environ["DONINO_PROXY_KEY"] = "budget-fixture-proxy-" + "x" * 40

    def node(self, name, *, secure=True):
        node = self.post("/nodes", {"name": name, "host": name + ".example.com"}).json()
        self.assertEqual(
            self.post(
                "/inbounds",
                {
                    "node_id": node["id"],
                    "name": name,
                    "protocol": "vless",
                    "port": 443,
                    "sni": "www.microsoft.com",
                },
            ).status_code,
            201,
        )
        if not secure:
            return node, {"Authorization": "Bearer " + node["token"]}
        token = self.post(f"/nodes/{node['id']}/enrollment").json()["token"]
        _, csr = certificate_request()
        result = self.client.post(
            "/api/agent/enroll",
            json={"node_id": node["id"], "token": token, "csr": csr},
        )
        self.assertEqual(result.status_code, 201)
        return node, {
            "X-Donino-Proxy-Key": os.environ["DONINO_PROXY_KEY"],
            "X-Donino-Client-Verify": "SUCCESS",
            "X-Donino-Client-Cert": quote(result.json()["certificate"], safe=""),
        }

    def shared(self):
        result = self.post(
            "/users", {"name": "shared", "quota": 1000, "quota_mode": "lease"}
        )
        self.assertEqual(result.status_code, 201)
        return result.json()

    def desired(self, auth, instance):
        result = self.client.get(
            "/api/agent/config", headers=auth, params={"instance": instance}
        )
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def usage(self, auth, user, lease, up, *, epoch="process", period=0):
        return self.client.post(
            "/api/agent/heartbeat",
            headers=auth,
            json={
                "epoch": epoch,
                "usage": [
                    {
                        "user_id": user["id"],
                        "period_no": period,
                        "lease_id": lease,
                        "up": up,
                        "down": 0,
                    }
                ],
            },
        )

    def test_concurrent_grants_never_allocate_the_same_credit_twice(self):
        self.shared()
        first, first_auth = self.node("first")
        second, second_auth = self.node("second")
        instances = [str(uuid.uuid4()), str(uuid.uuid4())]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda value: self.desired(*value),
                    [(first_auth, instances[0]), (second_auth, instances[1])],
                )
            )
        grants = [result["budgets"][0] for result in results]
        self.assertEqual(sum(grant["granted"] for grant in grants), 1000)
        for index, auth in enumerate((first_auth, second_auth)):
            self.assertEqual(
                self.desired(auth, instances[index])["budgets"][0]["id"],
                grants[index]["id"],
            )
        with database() as db:
            self.assertEqual(
                db.execute("SELECT SUM(granted) FROM budget_leases").fetchone()[0], 1000
            )
        self.assertEqual(
            self.client.get("/api/users").json()[0]["budget_reserved"], 1000
        )

    def test_expired_unreported_grant_stays_reserved_after_new_instance(self):
        user = self.shared()
        _, auth = self.node("first")
        old = self.desired(auth, str(uuid.uuid4()))["budgets"][0]
        with database() as db:
            db.execute("UPDATE budget_leases SET expires=1")
        new = self.desired(auth, str(uuid.uuid4()))
        self.assertEqual(new["budgets"], [])
        row = self.client.get("/api/users").json()[0]
        self.assertEqual(row["budget_unreconciled"], 1000)
        self.assertEqual(self.usage(auth, user, old["id"], 200).status_code, 200)
        self.assertEqual(self.desired(auth, str(uuid.uuid4()))["budgets"], [])
        row = self.client.get("/api/users").json()[0]
        self.assertEqual((row["used"], row["budget_reserved"]), (200, 800))

    def test_clean_closure_refunds_only_after_stop_and_ack_and_cannot_rebill(self):
        user = self.shared()
        node, auth = self.node("first")
        instance = str(uuid.uuid4())
        old = self.desired(auth, instance)["budgets"][0]
        self.assertEqual(self.usage(auth, user, old["id"], 200).status_code, 200)
        close = {
            "epoch": "process",
            "agent_instance": instance,
            "closed_leases": [old["id"]],
            "core_running": True,
        }
        self.assertEqual(
            self.client.post(
                "/api/agent/heartbeat", headers=auth, json=close
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.post(
                "/api/agent/heartbeat",
                headers=auth,
                json={
                    **close,
                    "core_running": False,
                    "agent_instance": str(uuid.uuid4()),
                },
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.post(
                "/api/agent/heartbeat",
                headers=auth,
                json={**close, "core_running": False},
            ).status_code,
            200,
        )
        self.assertEqual(self.usage(auth, user, old["id"], 200).status_code, 200)
        self.assertEqual(self.usage(auth, user, old["id"], 250).status_code, 409)
        new = self.desired(auth, str(uuid.uuid4()))["budgets"][0]
        self.assertEqual(new["granted"], 800)
        self.assertEqual(
            self.client.delete(
                f"/api/nodes/{node['id']}", headers=self.headers
            ).status_code,
            409,
        )

    def test_other_node_wrong_period_unlabeled_usage_refused_and_overshoot_retained(
        self,
    ):
        user = self.shared()
        _, auth = self.node("first")
        _, other_auth = self.node("second")
        grant = self.desired(auth, str(uuid.uuid4()))["budgets"][0]
        self.assertEqual(
            self.usage(other_auth, user, grant["id"], 100).status_code, 409
        )
        self.assertEqual(self.usage(auth, user, None, 100).status_code, 409)
        self.assertEqual(
            self.usage(auth, user, grant["id"], 100, period=99).status_code, 409
        )
        self.assertEqual(
            self.usage(auth, user, grant["id"], grant["granted"] + 50).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/users").json()[0]["used"], grant["granted"] + 50
        )
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM audit WHERE action='budget.sampled-overshoot'"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.usage(auth, user, grant["id"], grant["granted"] + 50).status_code, 200
        )

    def test_legacy_node_or_missing_instance_cannot_receive_shared_credentials(self):
        user = self.shared()
        node, auth = self.node("first", secure=False)
        desired = self.desired(auth, str(uuid.uuid4()))
        self.assertEqual(desired["budgets"], [])
        self.assertEqual(desired["config"]["inbounds"][1]["settings"]["clients"], [])
        secure_node, secure_auth = self.node("second")
        self.assertEqual(
            self.client.get("/api/agent/config", headers=secure_auth).json()["budgets"],
            [],
        )
        self.assertEqual(
            self.post(
                "/users", {"name": "unlimited-shared", "quota_mode": "lease"}
            ).status_code,
            422,
        )
        self.assertEqual(
            self.client.put(
                f"/api/users/{user['id']}",
                headers=self.headers,
                json={"name": "shared", "quota": 1000, "quota_mode": "legacy"},
            ).status_code,
            409,
        )

    def test_period_reset_isolates_old_reserved_and_delayed_consumption(self):
        user = self.shared()
        _, auth = self.node("first")
        instance = str(uuid.uuid4())
        old = self.desired(auth, instance)["budgets"][0]
        self.post(f"/users/{user['id']}/reset-traffic")
        new = self.desired(auth, instance)["budgets"][0]
        self.assertNotEqual(old["id"], new["id"])
        self.assertEqual(new["period_no"], 1)
        self.assertEqual(self.usage(auth, user, old["id"], 300).status_code, 200)
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 0)
        self.assertEqual(
            self.usage(
                auth, user, new["id"], 100, epoch="new-process", period=1
            ).status_code,
            200,
        )
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 100)

    def test_journal_totals_survive_pruning_and_concurrent_duplicate_samples(self):
        journal = UsageJournal(self.tmp.name + "/budget-journal.db")
        sample = {
            "user_id": "device",
            "period_no": 0,
            "lease_id": "grant",
            "up": 100,
            "down": 50,
        }
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: journal.record("first", [sample]), range(4)))
        journal.acknowledge("first", [sample])
        journal.prune("second")
        self.assertEqual(journal.budget_spent(), {"grant": 150})
        journal.record("second", [{**sample, "up": 10, "down": 20}])
        self.assertEqual(UsageJournal(journal.path).budget_spent(), {"grant": 180})

    def test_devices_share_one_grant_and_small_remaining_credit_is_not_doubled(self):
        user = self.shared()
        device = self.post(f"/users/{user['id']}/devices", {"name": "phone"}).json()
        _, first = self.node("first")
        _, second = self.node("second")
        instance = str(uuid.uuid4())
        grant = self.desired(first, instance)["budgets"][0]
        self.assertEqual(set(grant["devices"]), {user["id"], device["id"]})
        self.assertEqual(self.usage(first, user, grant["id"], 200).status_code, 200)
        self.assertEqual(self.usage(first, device, grant["id"], 250).status_code, 200)
        self.desired(first, instance)
        last = self.desired(second, str(uuid.uuid4()))["budgets"][0]
        self.assertEqual(last["granted"], 50)
        current = self.client.get("/api/users").json()[0]
        self.assertEqual((current["used"], current["budget_reserved"]), (450, 550))
