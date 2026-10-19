import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from app import ops
from app.db import (
    SCHEMA_VERSION,
    database,
    initialize,
    schema_version,
    set_schema_version,
)
from app.node_identity import public_material, verify_desired
from app.secrets import unseal
from agent.openvpn import OpenVPNAgent
from support import strip_openvpn_schema
from test_accounts import PanelBase
from test_wireguard import FakeKernel


class OpenVPNFixture(PanelBase):
    def setUp(self):
        super().setUp()
        self.node = self.post(
            "/nodes", {"name": "ovpn", "host": "vpn.example.com"}
        ).json()
        self.user = self.post("/users", {"name": "ovpn-user"}).json()
        r = self.post(
            "/openvpn/endpoints",
            {"node_id": self.node["id"], "name": "UDP VPN", "host": "vpn.example.com"},
        )
        self.assertEqual(r.status_code, 201, r.text)
        self.endpoint = r.json()
        r = self.post(
            f"/openvpn/endpoints/{self.endpoint['id']}/peers",
            {"device_id": self.user["id"]},
        )
        self.assertEqual(r.status_code, 201, r.text)
        self.peer = r.json()
        self.client.put(
            "/api/openvpn/endpoints/" + self.endpoint["id"],
            headers=self.headers,
            json={"enabled": True},
        )
        self.node_headers = {"Authorization": "Bearer " + self.node["token"]}

    def desired(self):
        return self.client.get(
            "/api/agent/openvpn/config",
            params={"instance": str(uuid.uuid4())},
            headers=self.node_headers,
        ).json()

    def profile(self):
        return self.client.get(
            "/api/openvpn/peers/" + self.peer["id"] + "/profile", headers=self.headers
        )


class OpenVPNAPITest(OpenVPNFixture):
    def test_pki_is_separate_private_and_profiles_pin_server_identity(self):
        p = self.profile()
        self.assertEqual(p.status_code, 200)
        self.assertEqual(p.headers["cache-control"], "no-store")
        self.assertIn(
            "verify-x509-name donino-" + self.endpoint["id"] + " name", p.text
        )
        self.assertIn("block-ipv6", p.text)
        self.assertIn("<tls-crypt>", p.text)
        with database() as db:
            e = db.execute("SELECT * FROM ovpn_endpoints").fetchone()
            peer = db.execute("SELECT * FROM ovpn_peers").fetchone()
            for field in ("ca_key", "server_key", "tls_key"):
                self.assertTrue(e[field].startswith("fernet:"))
                self.assertNotIn(unseal(e[field]), json.dumps(self.endpoint))
            self.assertTrue(peer["private_key"].startswith("fernet:"))
            ca = x509.load_pem_x509_certificate(e["ca_cert"].encode())
            cert = x509.load_pem_x509_certificate(peer["certificate"].encode())
            cert.verify_directly_issued_by(ca)
            self.assertIn(
                ExtendedKeyUsageOID.CLIENT_AUTH,
                cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
            )
            self.assertNotEqual(e["ca_cert"], public_material()["ca_certificate"])
            key = serialization.load_pem_private_key(
                unseal(peer["private_key"]).encode(), None
            )
            self.assertEqual(
                key.public_key().public_numbers(), cert.public_key().public_numbers()
            )
        body = verify_desired(
            self.desired(), public_material()["config_verify_key"], self.node["id"]
        )
        self.assertEqual(body["kind"], "openvpn-v1")
        i = body["interfaces"][0]
        self.assertNotIn("ca_key", i)
        self.assertNotIn("private_key", i["peers"][0])

    def test_owner_scope_validation_pool_and_serial_rotation(self):
        self.login("viewer")
        self.assertEqual(self.profile().status_code, 403)
        self.login()
        old = self.peer["serial"]
        self.post("/devices/" + self.user["id"] + "/rotate-secret")
        self.assertNotEqual(self.desired()["interfaces"][0]["peers"][0]["serial"], old)
        for pool in ("0.0.0.0/0", "127.0.0.0/24", "10.67.0.1/24"):
            r = self.post(
                "/openvpn/endpoints",
                {
                    "node_id": self.node["id"],
                    "name": "bad",
                    "host": "vpn.example",
                    "pool": pool,
                },
            )
            self.assertEqual(r.status_code, 422)
        r = self.post(
            "/openvpn/endpoints",
            {
                "node_id": self.node["id"],
                "name": "overlap",
                "host": "vpn.example",
                "port": 1195,
            },
        )
        self.assertEqual(r.status_code, 409)
        with database() as db:
            db.execute(
                "UPDATE users SET quota_mode='lease' WHERE id=?", (self.user["id"],)
            )
        self.assertEqual(self.desired()["interfaces"][0]["peers"], [])
        self.assertEqual(self.profile().status_code, 409)

    def test_restore_fences_endpoints_and_schema15_upgrade_is_backed_up(self):
        archive = Path(self.tmp.name) / "ovpn.backup"
        ops.backup(archive)
        ops.restore(archive, replace=True)
        self.login()
        self.assertEqual(self.profile().status_code, 409)
        with database() as db:
            strip_openvpn_schema(db)
            set_schema_version(db, 15)
        with patch("app.db.migration_backup", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                initialize()
        with database() as db:
            self.assertEqual(schema_version(db), 15)
        initialize()
        with database() as db:
            self.assertEqual(schema_version(db), SCHEMA_VERSION)


class OpenVPNAgentTest(OpenVPNFixture):
    def setUp(self):
        super().setUp()
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_PANEL_URL": "https://panel.example",
                "DONINO_OVPN_STATE": self.tmp.name + "/ovpn",
            },
        )
        self.env.start()
        client, headers = self.client, self.node_headers

        class LocalPanel:
            def get(self, path, **kwargs):
                return client.get(path, headers=headers, **kwargs)

            def post(self, path, **kwargs):
                return client.post(path, headers=headers, **kwargs)

            def close(self):
                pass

        self.identity = {
            "node_id": self.node["id"],
            "config_verify_key": public_material()["config_verify_key"],
            "expires": time.time() + 30 * 86400,
        }
        self.kernel = FakeKernel()
        self.agent = OpenVPNAgent(
            client=LocalPanel(), identity=self.identity, kernel=self.kernel
        )

    def tearDown(self):
        try:
            self.agent.close()
        finally:
            self.env.stop()
            super().tearDown()

    def test_period_usage_dedup_expiry_and_signature_authority(self):
        self.agent.tick()
        name = next(iter(self.kernel.links))
        self.kernel.links[name]["counters"][self.peer["id"]] = (123, 456)
        self.agent.tick()
        self.agent.tick()
        with database() as db:
            self.assertEqual(
                db.execute(
                    "SELECT used FROM users WHERE id=?", (self.user["id"],)
                ).fetchone()[0],
                579,
            )
        self.agent.deadline = time.monotonic() - 1
        self.agent.enforce()
        self.assertFalse(self.kernel.links)

    def test_local_quota_and_revoke_preserve_other_device_session(self):
        second = self.post(
            "/users/" + self.user["id"] + "/devices", {"name": "second"}
        ).json()
        peer = self.post(
            "/openvpn/endpoints/" + self.endpoint["id"] + "/peers",
            {"device_id": second["id"]},
        ).json()
        self.agent.tick()
        name = next(iter(self.kernel.links))
        self.kernel.links[name]["counters"][peer["id"]] = (20, 30)
        epoch = self.agent.epoch
        self.client.put(
            "/api/openvpn/peers/" + self.peer["id"],
            headers=self.headers,
            json={"enabled": False},
        )
        self.agent.tick()
        self.assertEqual(self.agent.epoch, epoch)
        self.assertEqual(self.kernel.links[name]["counters"][peer["id"]], (20, 30))
        with database() as db:
            db.execute("UPDATE users SET quota=60 WHERE id=?", (self.user["id"],))
        self.agent.tick()
        self.kernel.links[name]["counters"][peer["id"]] = (30, 40)
        self.agent.enforce()
        self.assertFalse(self.kernel.links[name]["counters"])
