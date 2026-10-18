import copy
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
from fastapi import HTTPException

from app import ops, smart_dns
from app.db import (
    SCHEMA_VERSION,
    database,
    initialize,
    schema_version,
    set_schema_version,
    table_exists,
)
from app.dns_service import DNSService
from app.secrets import PREFIX
from test_accounts import PanelBase
from support import strip_smart_schema


class SmartFixture(PanelBase):
    def setUp(self):
        super().setUp()
        os.environ.update(DONINO_SMART_DNS="1", DONINO_SMART_DNS_IPS="1.2.3.4")
        smart_dns.heartbeat("fixture")
        self.exit_body = {
            "name": "exit one",
            "host": "127.0.0.1",
            "port": 9445,
            "sni": "exit.example",
            "username": "fixture-user-123",
            "password": "fixture-private-password-12345",
            "mode": "disabled",
        }
        self.exit = self.add_exit(self.exit_body)
        self.rules = [
            {"domain": "example.com", "action": "route", "exit_ids": [self.exit["id"]]},
            {"domain": "blocked.example.com", "action": "block"},
            {"domain": "direct.example.com", "action": "allow"},
        ]
        policy = self.post("/dns/policies", {"name": "smart", "rules": self.rules})
        self.assertEqual(policy.status_code, 201, policy.text)
        self.policy = policy.json()
        self.user = self.post("/users", {"name": "smart-user"}).json()
        account = self.post(
            "/dns/accounts",
            {
                "user_id": self.user["id"],
                "policy_id": self.policy["id"],
                "relay_enabled": True,
                "relay_limit": 0,
            },
        )
        self.assertEqual(account.status_code, 201, account.text)
        self.account = account.json()
        with database() as db:
            db.execute(
                "INSERT INTO dns_ip_leases(ip,account_id,expires,created) VALUES(?,?,?,?)",
                (
                    "1.1.1.1",
                    self.account["id"],
                    int(time.time()) + 3600,
                    int(time.time()),
                ),
            )

    def add_exit(self, body):
        result = self.post("/dns/smart/exits", body)
        self.assertEqual(result.status_code, 201, result.text)
        row = result.json()
        smart_dns.health(
            row["id"], row["revision"], True, 10
        )  # Unit fixture's authenticated-peer observation.
        result = self.client.put(
            "/api/dns/smart/exits/" + row["id"],
            headers=self.headers,
            json={**body, "username": "", "password": "", "mode": "active"},
        )
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def opened(self):
        session = smart_dns.admit("1.1.1.1", "play.example.com")
        node = session["exits"][0]
        smart_dns.selected(session, node["id"], node["revision"])
        session["exit_revision"] = node["revision"]
        return session

    def answer(self, host="play.example.com", kind="A", **kwargs):
        return dns.message.from_wire(
            DNSService().answer(
                dns.message.make_query(host, kind).to_wire(),
                source_ip="1.1.1.1",
                **kwargs,
            )
        )


class SmartDNSTest(SmartFixture):
    def test_pending_fallback_renews_lease_but_does_not_survive_policy_change(self):
        session = smart_dns.admit("1.1.1.1", "play.example.com")
        now = int(time.time())
        with database() as db:
            db.execute("UPDATE smart_sessions SET lease_until=?", (now + 1,))
        smart_dns.connecting(session)
        with database() as db:
            self.assertGreaterEqual(
                db.execute("SELECT lease_until FROM smart_sessions").fetchone()[0],
                now + 10,
            )
            db.execute("UPDATE dns_policies SET revision='changed'")
        with self.assertRaises(HTTPException):
            smart_dns.connecting(session)
        with database() as db:
            db.execute("UPDATE dns_periods SET relay_up=1")
            db.execute("UPDATE dns_accounts SET relay_limit=1")
        self.assertEqual(self.answer().rcode(), dns.rcode.SERVFAIL)

    def test_real_front_lease_entitlement_and_source_ownership_gate_dns_routes(self):
        response = self.answer()
        self.assertEqual(response.answer[0][0].address, "1.2.3.4")
        self.assertEqual(response.answer[0].ttl, 30)
        self.assertFalse(response.flags & dns.flags.AD)
        self.assertEqual(self.answer("blocked.example.com").rcode(), dns.rcode.NXDOMAIN)
        self.assertFalse(self.answer(kind="AAAA").answer)
        self.assertFalse(self.answer(kind="HTTPS").answer)
        other = DNSService().answer(
            dns.message.make_query("play.example.com", "A").to_wire(),
            token=self.account["token"],
            source_ip="2.2.2.2",
        )
        self.assertEqual(dns.message.from_wire(other).rcode(), dns.rcode.SERVFAIL)
        for mutation in ("gateway", "entitlement", "exit"):
            with database() as db:
                if mutation == "gateway":
                    db.execute("UPDATE smart_gateway SET lease_until=1")
                elif mutation == "entitlement":
                    db.execute("UPDATE dns_accounts SET relay_enabled=0")
                else:
                    db.execute("UPDATE smart_exits SET mode='disabled'")
            self.assertEqual(self.answer().rcode(), dns.rcode.SERVFAIL)
            smart_dns.heartbeat("fixture")
            with database() as db:
                db.execute("UPDATE dns_accounts SET relay_enabled=1")
                db.execute("UPDATE smart_exits SET mode='active'")

    def test_exit_secrets_roles_confirmation_probe_and_route_reference_validation(self):
        with database() as db:
            stored = db.execute("SELECT password FROM smart_exits").fetchone()[0]
        self.assertTrue(stored.startswith(PREFIX))
        result = self.client.get("/api/dns/smart/exits")
        self.assertNotIn(self.exit_body["password"], result.text)
        self.assertNotIn(stored, result.text)
        invalid = self.post(
            "/dns/smart/exits", {**self.exit_body, "password": "private"}
        )
        self.assertEqual(invalid.status_code, 422)
        self.assertNotIn("private", invalid.text)
        changed = self.client.put(
            "/api/dns/smart/exits/" + self.exit["id"],
            headers=self.headers,
            json={**self.exit_body, "host": "changed.example", "mode": "active"},
        )
        self.assertEqual(changed.status_code, 409)
        missing = self.post(
            "/dns/policies",
            {
                "name": "missing",
                "rules": [
                    {
                        "domain": "a.example",
                        "action": "route",
                        "exit_ids": ["00000000-0000-0000-0000-000000000000"],
                    }
                ],
            },
        )
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(
            self.client.delete(
                "/api/dns/smart/exits/" + self.exit["id"], headers=self.headers
            ).status_code,
            409,
        )
        self.login("operator")
        self.assertEqual(self.post("/dns/smart/exits", self.exit_body).status_code, 403)
        self.assertEqual(
            self.post("/dns/smart/exits/" + self.exit["id"] + "/probe").status_code, 403
        )

    def test_atomic_byte_quota_counts_both_directions_once_and_never_vpn_or_dns_queries(
        self,
    ):
        session = self.opened()
        with database() as db:
            db.execute("UPDATE dns_accounts SET relay_limit=128")

        def send(direction):
            try:
                smart_dns.charge(session, direction, 32)
                return True
            except HTTPException:
                return False

        with ThreadPoolExecutor(8) as pool:
            successes = sum(pool.map(send, ["up", "down"] * 10))
        self.assertEqual(successes, 4)
        with database() as db:
            period = dict(db.execute("SELECT * FROM dns_periods").fetchone())
            self.assertEqual(period["relay_up"] + period["relay_down"], 128)
            self.assertEqual(period["queries"], 0)
            self.assertEqual(db.execute("SELECT used FROM users").fetchone()[0], 0)
            self.assertEqual(
                db.execute(
                    "SELECT SUM(uploaded+downloaded) FROM smart_sessions"
                ).fetchone()[0],
                128,
            )

    def test_connection_claims_source_reassignment_and_old_period_never_charge_new_owner(
        self,
    ):
        with database() as db:
            db.execute("UPDATE dns_accounts SET relay_connections=1")
        session = self.opened()
        with self.assertRaises(HTTPException):
            self.opened()
        smart_dns.charge(session, "up", 20)
        self.post("/dns/accounts/" + self.account["id"] + "/reset")
        with self.assertRaises(HTTPException):
            smart_dns.charge(session, "down", 10)
        smart_dns.finish(session, "period_changed")
        later = self.opened()
        smart_dns.charge(later, "down", 10)
        with database() as db:
            rows = list(db.execute("SELECT * FROM dns_periods ORDER BY period_no"))
            self.assertEqual((rows[0]["relay_up"], rows[1]["relay_down"]), (20, 10))
            db.execute("DELETE FROM dns_ip_leases")
        with self.assertRaises(HTTPException):
            smart_dns.charge(later, "up", 1)
        self.assertEqual(
            self.client.get("/api/dns/accounts").json()[0]["relay_down"], 10
        )

    def test_ordered_failover_drain_disable_policy_change_and_user_expiry(self):
        second = self.add_exit({**self.exit_body, "name": "second"})
        rules = copy.deepcopy(self.rules)
        rules[0]["exit_ids"].append(second["id"])
        result = self.client.put(
            "/api/dns/policies/" + self.policy["id"],
            headers=self.headers,
            json={"name": "smart", "rules": rules},
        )
        self.assertEqual(result.status_code, 200)
        session = self.opened()
        self.assertEqual(
            [r["id"] for r in session["exits"]], [self.exit["id"], second["id"]]
        )
        with database() as db:
            db.execute(
                "UPDATE smart_exits SET mode='drain' WHERE id=?", (self.exit["id"],)
            )
        smart_dns.charge(session, "up", 10)
        self.assertEqual(self.opened()["exits"][0]["id"], second["id"])
        with database() as db:
            db.execute(
                "UPDATE smart_exits SET mode='disabled' WHERE id=?", (self.exit["id"],)
            )
        with self.assertRaises(HTTPException):
            smart_dns.charge(session, "down", 1)
        later = self.opened()
        with database() as db:
            db.execute("UPDATE users SET expires=1")
        with self.assertRaises(HTTPException):
            smart_dns.charge(later, "up", 1)

    def test_gateway_lease_config_drift_stale_sessions_and_read_only_metadata(self):
        with self.assertRaises(RuntimeError):
            smart_dns.heartbeat("other")
        session = self.opened()
        with database() as db:
            db.execute("UPDATE smart_sessions SET lease_until=1")
        with self.assertRaises(HTTPException):
            smart_dns.charge(session, "down", 1)
        self.opened()
        self.assertNotIn(
            "play.example.com", self.client.get("/api/dns/smart/sessions").text
        )
        with patch.dict(os.environ, {"DONINO_SMART_DNS_IPS": "5.6.7.8"}):
            self.assertEqual(self.answer().rcode(), dns.rcode.SERVFAIL)
        with patch.dict(os.environ, {"DONINO_SMART_DNS": "0"}):
            self.assertEqual(self.answer().rcode(), dns.rcode.SERVFAIL)
            with self.assertRaises(HTTPException):
                self.opened()

    def test_schema12_upgrade_backups_failure_and_restore_disable_egress_permissions(
        self,
    ):
        with database() as db:
            db.execute("UPDATE dns_policies SET rules='[]'")
            strip_smart_schema(db)
            set_schema_version(db, 12)
        with patch("app.db.migration_backup", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 12)
            self.assertFalse(table_exists(db, "smart_exits"))
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), SCHEMA_VERSION)
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM dns_accounts").fetchone()[0], 1
            )
        self.assertTrue(list(Path(self.tmp.name).glob(f"*.pre-v{SCHEMA_VERSION}-*")))
        self.exit = self.add_exit(self.exit_body)
        with database() as db:
            db.execute("UPDATE dns_accounts SET relay_enabled=1")
        backup = Path(self.tmp.name) / "smart.backup"
        ops.backup(backup)
        ops.restore(backup, replace=True)
        with database() as db:
            self.assertEqual(
                db.execute("SELECT mode FROM smart_exits").fetchone()[0], "disabled"
            )
            self.assertEqual(
                db.execute("SELECT relay_enabled FROM dns_accounts").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM smart_gateway").fetchone()[0], 0
            )
