from test_accounts import PanelBase
from app.gaming_catalog import catalog, compile_policy, CatalogPolicyInput
from app.db import database


class GamingCatalogTest(PanelBase):
    def test_pinned_catalog_compiles_all_groups_without_activating_a_relay(self):
        source = catalog()
        self.assertEqual(
            source["counts"], {"services": 42, "groups": 48, "domains": 505}
        )
        self.assertFalse(source["relay_available"])
        policy = CatalogPolicyInput(
            name="catalog all",
            groups=[
                {"service": s["key"], "group": g["key"]}
                for s in source["services"]
                for g in s["groups"]
            ],
            relay_addresses=["1.2.3.4"],
            domains_off=["playstation.net"],
        )
        compiled = compile_policy(policy)
        self.assertEqual(len(compiled.rules), 505)
        self.assertEqual(
            next(r.action for r in compiled.rules if r.domain == "playstation.net"),
            "allow",
        )
        result = self.post("/dns/policies/from-catalog", policy.model_dump())
        self.assertEqual(result.status_code, 201, result.text)
        self.assertFalse(result.json()["relay_available"])
        self.assertEqual(result.json()["rules"], 505)
        self.assertEqual(self.client.get("/api/dns/accounts").json(), [])

    def test_unknown_selection_is_atomic_and_operator_cannot_create_policies(self):
        body = {
            "name": "no partial",
            "groups": [
                {"service": "playstation", "group": "online"},
                {"service": "unknown", "group": "online"},
            ],
            "relay_addresses": ["1.2.3.4"],
        }
        self.assertEqual(self.post("/dns/policies/from-catalog", body).status_code, 422)
        with database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM dns_policies").fetchone()[0], 0
            )
        self.login("operator")
        self.assertEqual(self.post("/dns/policies/from-catalog", body).status_code, 403)
