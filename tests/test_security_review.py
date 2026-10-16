import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from test_accounts import PanelBase, PASSWORD, current_code
from app.db import database, initialize, set_schema_version
from app.main import app
from app.secrets import key_path, unseal


class SecurityReviewTest(PanelBase):
    def test_mfa_seed_encrypted_and_existing_plaintext_migrates(self):
        setup = self.post("/account/mfa/setup", {"password": PASSWORD}).json()
        with database() as db:
            row = db.execute("SELECT secret FROM admin_mfa").fetchone()
            self.assertNotEqual(row["secret"], setup["secret"])
            self.assertEqual(unseal(row["secret"]), setup["secret"])
            db.execute("UPDATE admin_mfa SET secret=?", (setup["secret"],))
            db.execute("DROP TABLE usage_periods")
            db.execute("DROP TABLE user_nodes")
            db.execute("DROP TABLE deployments")
            db.execute("ALTER TABLE nodes DROP COLUMN desired_job")
            db.execute("ALTER TABLE counters DROP COLUMN period_no")
            db.execute("ALTER TABLE users DROP COLUMN node_mode")
            set_schema_version(db, 4)
        self.assertEqual(key_path().stat().st_mode & 0o777, 0o600)
        initialize()
        with database() as db:
            self.assertEqual(
                unseal(db.execute("SELECT secret FROM admin_mfa").fetchone()[0]),
                setup["secret"],
            )

    def test_mfa_setup_requires_password_and_failures_are_committed(self):
        for _ in range(10):
            self.assertEqual(
                self.post("/account/mfa/setup", {"password": "wrong"}).status_code, 401
            )
        self.assertEqual(
            self.post("/account/mfa/setup", {"password": PASSWORD}).status_code, 429
        )
        with database() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM admin_mfa").fetchone()[0], 0
            )

    def test_mfa_transition_revokes_other_sessions_and_tokens(self):
        other = TestClient(app)
        self.assertEqual(self.login(client=other).status_code, 200)
        token = self.post("/account/tokens", {"name": "old", "scope": "full"}).json()[
            "token"
        ]
        secret, codes = self.enable_mfa()
        self.assertEqual(other.get("/api/me").status_code, 401)
        self.assertEqual(
            other.get(
                "/api/me", headers={"Authorization": "Bearer " + token}
            ).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/me").status_code, 200)
        self.login(code=current_code(secret, 1), client=other)
        token = self.post(
            "/account/tokens", {"name": "second", "scope": "full"}
        ).json()["token"]
        result = self.post(
            "/account/mfa/disable", {"password": PASSWORD, "code": codes[0]}
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(other.get("/api/me").status_code, 401)
        self.assertEqual(
            other.get(
                "/api/me", headers={"Authorization": "Bearer " + token}
            ).status_code,
            401,
        )

    def test_cli_password_reset_revokes_api_tokens(self):
        from app.cli import main

        token = self.post("/account/tokens", {"name": "old", "scope": "full"}).json()[
            "token"
        ]
        with (
            patch("sys.argv", ["donino", "admin", "owner"]),
            patch("getpass.getpass", return_value="replacement-password-123"),
        ):
            main()
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(
            self.client.get(
                "/api/me", headers={"Authorization": "Bearer " + token}
            ).status_code,
            401,
        )

    def test_unknown_database_url_cannot_silently_start_sqlite(self):
        with patch.dict(
            os.environ, {"DONINO_DATABASE_URL": "postgresql+misspelled://invalid"}
        ):
            with self.assertRaisesRegex(RuntimeError, "Unsupported"):
                with database():
                    pass
