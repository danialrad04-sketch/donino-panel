"""Phase 1 coverage: 2FA, API tokens, sessions, devices and paginated users."""

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from support import configure, sqlite_only
from app.db import database, hash_password, SCHEMA_VERSION
from app.main import app
from app.security import hotp, totp_verify, new_totp_secret, normalize_recovery

PASSWORD = "long-test-password"


def current_code(secret, offset=0):
    step = int(time.time() // 30) + offset
    return hotp(secret, step)


class PanelBase(unittest.TestCase):
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
                    (role, hash_password(PASSWORD), role),
                )
        self.headers = {"X-Donino": "1"}
        self.assertEqual(self.login().status_code, 200)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self.old)
        self.tmp.cleanup()

    def login(self, role="owner", code=None, client=None):
        body = {"username": role, "password": PASSWORD}
        if code:
            body["code"] = code
        return (client or self.client).post(
            "/api/login", headers=self.headers, json=body
        )

    def post(self, path, body=None, client=None, headers=None):
        return (client or self.client).post(
            "/api" + path, headers={**self.headers, **(headers or {})}, json=body
        )

    def enable_mfa(self):
        setup = self.post("/account/mfa/setup").json()
        code = current_code(setup["secret"])
        result = self.post("/account/mfa/enable", {"code": code})
        self.assertEqual(result.status_code, 200, result.text)
        return setup["secret"], result.json()["recovery_codes"]



class AccountTest(PanelBase):
    # --- 2FA -------------------------------------------------------------

    def test_totp_rfc6238_vector_and_replay_protection(self):
        # RFC 6238 test secret "12345678901234567890" in base32.
        import base64

        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(hotp(secret, 1, digits=8), "94287082")
        now = 59
        step = totp_verify(secret, "287082", 0, now=now, digits=6)
        self.assertEqual(step, 1)
        # Same code cannot be used again once its step is recorded.
        self.assertIsNone(totp_verify(secret, "287082", 1, now=now))

    def test_mfa_enable_requires_code_and_login_then_needs_second_factor(self):
        secret, codes = self.enable_mfa()
        self.assertEqual(len(codes), 10)
        self.assertEqual(self.client.get("/api/account").json()["mfa_enabled"], True)

        other = TestClient(app)
        step_one = self.login(client=other)
        self.assertEqual(step_one.status_code, 202)
        self.assertTrue(step_one.json()["mfa_required"])
        self.assertEqual(other.get("/api/me").status_code, 401)

        wrong = self.login(code="000000", client=other)
        self.assertEqual(wrong.status_code, 401)

        # The enrolment code was already consumed; a fresh one from the next step works.
        good = self.login(code=current_code(secret, offset=1), client=other)
        self.assertEqual(good.status_code, 200, good.text)
        self.assertEqual(other.get("/api/me").status_code, 200)

    def test_recovery_code_is_single_use(self):
        _, codes = self.enable_mfa()
        other = TestClient(app)
        code = codes[0]
        self.assertEqual(self.login(code=code, client=other).status_code, 200)
        third = TestClient(app)
        self.assertEqual(self.login(code=code, client=third).status_code, 401)
        self.assertEqual(normalize_recovery(" " + code.upper() + " "), code.replace("-", ""))

    def test_mfa_disable_needs_password_and_code(self):
        secret, _ = self.enable_mfa()
        bad = self.post(
            "/account/mfa/disable",
            {"password": "nope-nope-nope", "code": current_code(secret, 1)},
        )
        self.assertEqual(bad.status_code, 401)
        good = self.post(
            "/account/mfa/disable",
            {"password": PASSWORD, "code": current_code(secret, 1)},
        )
        self.assertEqual(good.status_code, 200, good.text)
        self.assertFalse(self.client.get("/api/account").json()["mfa_enabled"])

    def test_mfa_failures_share_lockout(self):
        self.enable_mfa()
        other = TestClient(app)
        for _ in range(10):
            self.assertEqual(self.login(code="111111", client=other).status_code, 401)
        self.assertEqual(self.login(code="111111", client=other).status_code, 429)

    # --- API tokens ------------------------------------------------------

    def test_token_scopes_and_expiry(self):
        created = self.post(
            "/account/tokens", {"name": "monitor", "scope": "read", "days": 1}
        ).json()
        token = created["token"]
        self.assertTrue(token.startswith("dnk_"))
        bearer = {"Authorization": "Bearer " + token}
        api = TestClient(app)
        self.assertEqual(api.get("/api/users", headers=bearer).status_code, 200)
        # Read scope cannot mutate, even without the X-Donino header.
        denied = api.post("/api/users", json={"name": "x"}, headers=bearer)
        self.assertEqual(denied.status_code, 403)
        # A token never falls back to the cookie session when invalid.
        self.assertEqual(
            api.get(
                "/api/users",
                headers={"Authorization": "Bearer dnk_bogus"},
            ).status_code,
            401,
        )
        with database() as db:
            db.execute("UPDATE api_tokens SET expires=0")
        self.assertEqual(api.get("/api/users", headers=bearer).status_code, 401)

    def test_users_scope_cannot_manage_nodes_or_read_audit(self):
        token = self.post(
            "/account/tokens", {"name": "automation", "scope": "users", "days": 7}
        ).json()["token"]
        bearer = {"Authorization": "Bearer " + token}
        api = TestClient(app)
        created = api.post("/api/users", json={"name": "api-made"}, headers=bearer)
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(
            api.post(
                "/api/nodes", json={"name": "x", "host": "example.com"}, headers=bearer
            ).status_code,
            403,
        )
        self.assertEqual(api.get("/api/audit", headers=bearer).status_code, 403)

    def test_token_cannot_manage_account_security(self):
        token = self.post(
            "/account/tokens", {"name": "full", "scope": "full", "days": 7}
        ).json()["token"]
        bearer = {"Authorization": "Bearer " + token}
        api = TestClient(app)
        self.assertEqual(
            api.post("/api/account/tokens", json={"name": "x", "scope": "full"}, headers=bearer).status_code,
            403,
        )
        self.assertEqual(
            api.post("/api/account/password", json={"current": PASSWORD, "new": "another-long-password"}, headers=bearer).status_code,
            403,
        )

    def test_token_listing_never_returns_plain_secret(self):
        created = self.post(
            "/account/tokens", {"name": "x", "scope": "read", "days": 3}
        ).json()
        listing = self.client.get("/api/account").text
        self.assertNotIn(created["token"], listing)
        self.assertIn(created["id"], listing)

    def test_revoke_token(self):
        created = self.post(
            "/account/tokens", {"name": "x", "scope": "read", "days": 3}
        ).json()
        self.assertEqual(
            self.client.delete("/api/account/tokens/" + created["id"], headers=self.headers).status_code,
            200,
        )
        api = TestClient(app)
        self.assertEqual(
            api.get("/api/users", headers={"Authorization": "Bearer " + created["token"]}).status_code,
            401,
        )

    # --- sessions and password -------------------------------------------

    def test_session_listing_and_revocation(self):
        other = TestClient(app)
        self.assertEqual(self.login(client=other).status_code, 200)
        sessions = self.client.get("/api/account").json()["sessions"]
        self.assertEqual(len(sessions), 2)
        current = [s for s in sessions if s["current"]]
        self.assertEqual(len(current), 1)
        others = [s for s in sessions if not s["current"]]
        self.assertEqual(
            self.client.delete("/api/account/sessions/" + others[0]["sid"], headers=self.headers).status_code,
            200,
        )
        self.assertEqual(other.get("/api/me").status_code, 401)
        self.assertEqual(self.client.get("/api/me").status_code, 200)

    def test_revoke_other_sessions_keeps_current(self):
        other = TestClient(app)
        self.login(client=other)
        self.assertEqual(self.post("/account/sessions/revoke-others").status_code, 200)
        self.assertEqual(other.get("/api/me").status_code, 401)
        self.assertEqual(self.client.get("/api/me").status_code, 200)

    def test_password_change_revokes_other_sessions_and_tokens(self):
        other = TestClient(app)
        self.login(client=other)
        token = self.post(
            "/account/tokens", {"name": "x", "scope": "full", "days": 3}
        ).json()["token"]
        result = self.post(
            "/account/password",
            {"current": PASSWORD, "new": "brand-new-password-1"},
        )
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(other.get("/api/me").status_code, 401)
        api = TestClient(app)
        self.assertEqual(
            api.get("/api/me", headers={"Authorization": "Bearer " + token}).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/me").status_code, 200)
        self.assertEqual(self.login(client=TestClient(app)).status_code, 401)
        self.assertEqual(
            self.login().status_code, 401, "old password must be refused"
        )

    # --- devices ---------------------------------------------------------

    def test_default_device_keeps_user_identity_and_credential(self):
        user = self.post("/users", {"name": "alice"}).json()
        devices = self.client.get("/api/users/" + user["id"] + "/devices").json()
        self.assertEqual(len(devices), 1)
        self.assertTrue(devices[0]["is_default"])
        self.assertEqual(devices[0]["id"], user["id"])
        with database() as db:
            secret = db.execute("SELECT secret FROM devices WHERE id=?", (user["id"],)).fetchone()[0]
            credential = db.execute("SELECT credential FROM users WHERE id=?", (user["id"],)).fetchone()[0]
        self.assertEqual(secret, credential)

    def test_default_device_cannot_be_deleted_but_others_can(self):
        user = self.post("/users", {"name": "bob"}).json()
        default = user["id"]
        self.assertEqual(
            self.client.delete("/api/devices/" + default, headers=self.headers).status_code, 409
        )
        phone = self.post("/users/" + user["id"] + "/devices", {"name": "phone"})
        self.assertEqual(phone.status_code, 201, phone.text)
        did = phone.json()["id"]
        self.assertNotIn("secret", phone.text)
        self.assertEqual(
            self.client.delete("/api/devices/" + did, headers=self.headers).status_code, 200
        )

    def test_device_limit_and_duplicate_name(self):
        user = self.post("/users", {"name": "carol"}).json()
        self.assertEqual(
            self.post("/users/" + user["id"] + "/devices", {"name": "phone"}).status_code, 201
        )
        self.assertEqual(
            self.post("/users/" + user["id"] + "/devices", {"name": "phone"}).status_code, 409
        )

    def test_device_rotation_changes_only_that_secret(self):
        user = self.post("/users", {"name": "dave"}).json()
        phone = self.post("/users/" + user["id"] + "/devices", {"name": "phone"}).json()
        with database() as db:
            before = dict(db.execute("SELECT id,secret FROM devices").fetchall())
        self.post("/devices/" + phone["id"] + "/rotate-secret")
        with database() as db:
            after = dict(db.execute("SELECT id,secret FROM devices").fetchall())
        self.assertNotEqual(before[phone["id"]], after[phone["id"]])
        self.assertEqual(before[user["id"]], after[user["id"]])

    def test_disabled_device_is_removed_from_node_config(self):
        from app.db import database as _db  # noqa: F401

        user = self.post("/users", {"name": "erin"}).json()
        node = self.post("/nodes", {"name": "n", "host": "example.com"}).json()
        phone = self.post("/users/" + user["id"] + "/devices", {"name": "phone"}).json()
        self.post(
            "/inbounds",
            {
                "node_id": node["id"],
                "name": "t",
                "protocol": "trojan",
                "port": 9443,
                "sni": "example.com",
                "cert_file": "/tmp/c.pem",
                "key_file": "/tmp/k.pem",
            },
        )
        auth = {"Authorization": "Bearer " + node["token"]}

        def emails():
            config = self.client.get("/api/agent/config", headers=auth).json()
            return sorted(c["email"] for c in config["config"]["inbounds"][1]["settings"]["clients"])

        self.assertEqual(emails(), sorted([user["id"], phone["id"]]))
        self.client.put(
            "/api/devices/" + phone["id"],
            headers=self.headers,
            json={"name": "phone", "enabled": False},
        )
        self.assertEqual(emails(), [user["id"]])

    def test_usage_is_counted_per_device_and_summed_per_user(self):
        user = self.post("/users", {"name": "frank"}).json()
        node = self.post("/nodes", {"name": "n", "host": "example.com"}).json()
        phone = self.post("/users/" + user["id"] + "/devices", {"name": "phone"}).json()
        auth = {"Authorization": "Bearer " + node["token"]}
        self.client.post(
            "/api/agent/heartbeat",
            headers=auth,
            json={
                "epoch": "e1",
                "usage": [
                    {"user_id": user["id"], "up": 10, "down": 20},
                    {"user_id": phone["id"], "up": 1, "down": 2},
                ],
            },
        )
        row = self.client.get("/api/users").json()[0]
        self.assertEqual(row["used"], 33)
        devices = {d["id"]: d for d in self.client.get("/api/users/" + user["id"] + "/devices").json()}
        self.assertEqual((devices[phone["id"]]["uploaded"], devices[phone["id"]]["downloaded"]), (1, 2))
        self.assertEqual((devices[user["id"]]["uploaded"], devices[user["id"]]["downloaded"]), (10, 20))

    def test_legacy_agent_sending_user_id_still_counts(self):
        user = self.post("/users", {"name": "gina"}).json()
        node = self.post("/nodes", {"name": "n", "host": "example.com"}).json()
        result = self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": "Bearer " + node["token"]},
            json={"epoch": "e", "usage": [{"user_id": user["id"], "up": 5, "down": 5}]},
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], 10)

    # --- pagination ------------------------------------------------------

    def test_paginated_users_with_search_and_state(self):
        for i in range(7):
            self.post("/users", {"name": f"user-{i}"})
        self.post("/users", {"name": "disabled-one", "enabled": False})
        page = self.client.get("/api/users?limit=3&offset=0", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["x-total-count"], "8")
        self.assertEqual(len(page.json()), 3)
        second = self.client.get("/api/users?limit=3&offset=3").json()
        self.assertEqual(len(second), 3)
        self.assertFalse({u["id"] for u in page.json()} & {u["id"] for u in second})
        found = self.client.get("/api/users?limit=50&q=user-3").json()
        self.assertEqual([u["name"] for u in found], ["user-3"])
        disabled = self.client.get("/api/users?limit=50&state=disabled").json()
        self.assertEqual([u["name"] for u in disabled], ["disabled-one"])
        active = self.client.get("/api/users?limit=50&state=active", headers=self.headers)
        self.assertEqual(active.headers["x-total-count"], "7")

    def test_search_treats_wildcards_literally(self):
        self.post("/users", {"name": "plain"})
        found = self.client.get("/api/users?limit=50&q=%25").json()
        self.assertEqual(found, [])

    def test_legacy_list_without_limit_still_returns_array(self):
        self.post("/users", {"name": "legacy-shape"})
        body = self.client.get("/api/users").json()
        self.assertIsInstance(body, list)


@sqlite_only
class MigrationV3Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "donino.db"
        self.env = patch.dict(os.environ, {"DONINO_DB": str(self.path)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_v3_upgrade_preserves_identity_counters_and_sessions(self):
        from app.db import initialize, migrate_to_v3

        with sqlite3.connect(self.path) as db:
            db.executescript((Path(__file__).parent / "fixtures/v0.1.sql").read_text())
            db.execute(
                "INSERT INTO users(id,credential,name,used,token,created) VALUES(?,?,?,?,?,?)",
                ("u-1", "cred-1", "old-user", 321, "tok-1", 123),
            )
            db.execute(
                "INSERT INTO nodes(id,name,host,token) VALUES(?,?,?,?)",
                ("n-1", "node", "example.com", "node-hash"),
            )
            db.execute(
                "INSERT INTO counters(node_id,epoch,user_id,up,down) VALUES(?,?,?,?,?)",
                ("n-1", "epoch-a", "u-1", 100, 200),
            )
            db.execute(
                "INSERT INTO sessions(token,username,expires) VALUES(?,?,?)",
                ("sess-hash", "owner", int(time.time()) + 1000),
            )
            # Build a true v2 schema by running the v2 steps only.
            db.execute("PRAGMA user_version=0")
        with sqlite3.connect(self.path) as db:
            db.execute("ALTER TABLE users ADD COLUMN uploaded INTEGER NOT NULL DEFAULT 0")
            db.execute("ALTER TABLE users ADD COLUMN downloaded INTEGER NOT NULL DEFAULT 0")
            db.execute("ALTER TABLE users ADD COLUMN legacy_used INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE users SET legacy_used=used")
            db.execute("ALTER TABLE nodes ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''")
            db.execute("ALTER TABLE nodes ADD COLUMN apply_mode TEXT NOT NULL DEFAULT ''")
            db.execute("ALTER TABLE nodes ADD COLUMN core_running INTEGER")
            db.execute("ALTER TABLE nodes ADD COLUMN pending_usage INTEGER NOT NULL DEFAULT 0")
            db.execute("PRAGMA user_version=2")
        initialize()
        with database() as db:
            self.assertEqual(
                db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
            )
            device = db.execute("SELECT * FROM devices").fetchone()
            self.assertEqual((device["id"], device["secret"], device["is_default"]), ("u-1", "cred-1", 1))
            counter = db.execute("SELECT * FROM counters").fetchone()
            self.assertEqual((counter["device_id"], counter["up"], counter["down"]), ("u-1", 100, 200))
            session = db.execute("SELECT sid, created FROM sessions").fetchone()
            self.assertIsNotNone(session["sid"])
            user = db.execute("SELECT used, legacy_used, token FROM users").fetchone()
            self.assertEqual((user["used"], user["legacy_used"], user["token"]), (321, 321, "tok-1"))
        backups = list(self.path.parent.glob("*.pre-v%d-*.db" % SCHEMA_VERSION))
        self.assertEqual(len(backups), 1)

    def test_future_schema_still_refused(self):
        from app.db import initialize

        with sqlite3.connect(self.path) as db:
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        with self.assertRaises(RuntimeError):
            initialize()


class AdminManagementTest(PanelBase):
    def test_owner_can_create_operator_and_change_role(self):
        created = self.post("/admins", {"username": "ops", "password": "operator-password-1", "role": "operator"})
        self.assertEqual(created.status_code, 201, created.text)
        listing = {a["username"]: a for a in self.client.get("/api/admins").json()}
        self.assertEqual(listing["ops"]["role"], "operator")
        changed = self.client.put("/api/admins/ops", headers=self.headers, json={"role": "viewer"})
        self.assertEqual(changed.status_code, 200, changed.text)

    def test_role_change_ends_that_admins_sessions(self):
        self.post("/admins", {"username": "ops", "password": "operator-password-1", "role": "operator"})
        ops = TestClient(app)
        ops_login = ops.post("/api/login", headers=self.headers, json={"username": "operator", "password": PASSWORD})
        self.assertEqual(ops_login.status_code, 200, ops_login.text)
        self.client.put("/api/admins/operator", headers=self.headers, json={"role": "viewer"})
        self.assertEqual(ops.get("/api/me").status_code, 401)

    def test_last_owner_cannot_be_demoted_or_deleted(self):
        self.assertEqual(
            self.client.put("/api/admins/owner", headers=self.headers, json={"role": "viewer"}).status_code, 409
        )
        self.assertEqual(self.client.delete("/api/admins/owner", headers=self.headers).status_code, 409)

    def test_cannot_delete_own_account(self):
        self.post("/admins", {"username": "second", "password": "second-owner-pass-1", "role": "owner"})
        self.assertEqual(self.client.delete("/api/admins/owner", headers=self.headers).status_code, 409)

    def test_non_owner_cannot_manage_admins(self):
        self.post("/admins", {"username": "ops", "password": "operator-password-1", "role": "operator"})
        ops = TestClient(app)
        self.login("operator", client=ops)
        self.assertEqual(ops.get("/api/admins").status_code, 403)

    def test_token_cannot_manage_admins(self):
        token = self.post("/account/tokens", {"name": "full", "scope": "full", "days": 3}).json()["token"]
        api = TestClient(app)
        self.assertEqual(
            api.post("/api/admins", json={"username": "x", "password": "another-long-pass-1", "role": "owner"},
                     headers={"Authorization": "Bearer " + token}).status_code, 403)

    def test_password_reset_revokes_that_admin(self):
        self.post("/admins", {"username": "ops", "password": "operator-password-1", "role": "operator"})
        ops = TestClient(app)
        ops.post("/api/login", headers=self.headers, json={"username": "operator", "password": PASSWORD})
        result = self.post("/admins/operator/password", {"password": "reset-password-123"})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(ops.get("/api/me").status_code, 401)


class PeriodTest(PanelBase):
    def test_monthly_period_starts_on_first_usage_and_resets(self):
        user = self.post("/users", {"name": "monthly", "quota": 1000, "period": "monthly", "period_days": 30}).json()
        node = self.post("/nodes", {"name": "n", "host": "example.com"}).json()
        auth = {"Authorization": "Bearer " + node["token"]}
        self.assertIsNone(self.client.get("/api/users").json()[0].get("period_start"))
        self.client.post("/api/agent/heartbeat", headers=auth,
                         json={"epoch": "e", "usage": [{"user_id": user["id"], "up": 300, "down": 0}]})
        with database() as db:
            start = db.execute("SELECT period_start FROM users WHERE id=?", (user["id"],)).fetchone()[0]
        self.assertIsNotNone(start)
        # Simulate the period ending.
        with database() as db:
            db.execute("UPDATE users SET period_start=? WHERE id=?", (start - 31 * 86400, user["id"]))
        self.client.post("/api/agent/heartbeat", headers=auth,
                         json={"epoch": "e", "usage": [{"user_id": user["id"], "up": 300, "down": 0}]})
        row = self.client.get("/api/users").json()[0]
        # Counter baseline is kept: the unchanged cumulative value bills nothing again.
        self.assertEqual(row["used"], 0)
        self.assertEqual(row["period_no"], 1)

    def test_period_end_reactivates_limited_user(self):
        user = self.post("/users", {"name": "limited", "quota": 100, "period": "monthly", "period_days": 30}).json()
        node = self.post("/nodes", {"name": "n", "host": "example.com"}).json()
        auth = {"Authorization": "Bearer " + node["token"]}
        self.client.post("/api/agent/heartbeat", headers=auth,
                         json={"epoch": "e", "usage": [{"user_id": user["id"], "up": 150, "down": 0}]})
        self.assertEqual(self.client.get("/api/users").json()[0]["status"], "limited")
        with database() as db:
            db.execute("UPDATE users SET period_start=? WHERE id=?", (int(time.time()) - 31 * 86400, user["id"]))
        from app.main import roll_periods
        with database() as db:
            self.assertEqual(roll_periods(db), 1)
        self.assertEqual(self.client.get("/api/users").json()[0]["status"], "active")

    def test_switching_to_none_clears_period_start(self):
        user = self.post("/users", {"name": "p", "period": "monthly", "period_days": 30}).json()
        with database() as db:
            db.execute("UPDATE users SET period_start=123 WHERE id=?", (user["id"],))
        self.client.put("/api/users/" + user["id"], headers=self.headers,
                        json={"name": "p", "period": "none", "period_days": 30})
        with database() as db:
            self.assertIsNone(db.execute("SELECT period_start FROM users WHERE id=?", (user["id"],)).fetchone()[0])

    def test_legacy_user_body_defaults_to_no_period(self):
        user = self.post("/users", {"name": "legacy"}).json()
        self.assertEqual(user.get("period"), "none")


if __name__ == "__main__":
    unittest.main()
