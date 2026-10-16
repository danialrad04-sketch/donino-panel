import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote


from test_accounts import PanelBase
from agent.identity import certificate_request, load_identity, save_identity
from app.db import database
from app.node_identity import public_material, sign_desired, verify_desired
from app.main import app
from fastapi.testclient import TestClient


class NodeIdentityTest(PanelBase):
    def setUp(self):
        super().setUp()
        os.environ["DONINO_PROXY_KEY"] = "fixture-proxy-key-" + "x" * 40

    def setup_node(self):
        node = self.post(
            "/nodes", {"name": "secure-node", "host": "vpn.example.com"}
        ).json()
        token = self.post(f"/nodes/{node['id']}/enrollment").json()
        private, csr = certificate_request()
        return node, token, private, csr

    def enroll(self, node, token, csr):
        return self.client.post(
            "/api/agent/enroll",
            json={"node_id": node["id"], "token": token["token"], "csr": csr},
        )

    def trusted_headers(self, certificate):
        return {
            "X-Donino-Client-Cert": quote(certificate, safe=""),
            "X-Donino-Client-Verify": "SUCCESS",
            "X-Donino-Proxy-Key": "fixture-proxy-key-" + "x" * 40,
        }

    def test_enrollment_atomic_retry_same_csr_only_and_bearer_is_retired(self):
        node, token, private, csr = self.setup_node()
        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(
                workers.map(lambda _: self.enroll(node, token, csr), range(4))
            )
        self.assertEqual([result.status_code for result in results], [201] * 4)
        certs = {result.json()["certificate"] for result in results}
        self.assertEqual(len(certs), 1)
        _, different_csr = certificate_request()
        self.assertEqual(self.enroll(node, token, different_csr).status_code, 401)
        self.assertEqual(
            self.client.get(
                "/api/agent/config",
                headers={"Authorization": "Bearer " + node["token"]},
            ).status_code,
            401,
        )
        self.assertEqual(
            self.post(f"/nodes/{node['id']}/rotate-token").status_code, 409
        )
        with database() as db:
            row = db.execute("SELECT * FROM node_enrollments").fetchone()
            self.assertNotIn(token["token"], str(dict(row)))
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM node_certificates").fetchone()[0], 1
            )
        result = results[0].json()
        root = Path(self.tmp.name) / "node"
        save_identity(root, "https://panel.example.com", node["id"], result, private)
        save_identity(root, "https://panel.example.com", node["id"], result, private)
        self.assertEqual(
            load_identity(root, "https://panel.example.com")["node_id"], node["id"]
        )
        self.assertEqual(
            (
                root
                / load_identity(root, "https://panel.example.com")["directory"]
                / "client.key"
            )
            .stat()
            .st_mode
            & 0o777,
            0o600,
        )

    def test_proxy_spoofing_rejected_revocation_immediate_and_no_bearer_fallback(self):
        node, token, _, csr = self.setup_node()
        result = self.enroll(node, token, csr).json()
        headers = self.trusted_headers(result["certificate"])
        with patch.dict(
            os.environ, {"DONINO_PROXY_KEY": headers["X-Donino-Proxy-Key"]}
        ):
            for key, bad in (
                ("X-Donino-Proxy-Key", "wrong"),
                ("X-Donino-Client-Verify", "NONE"),
            ):
                self.assertEqual(
                    self.client.get(
                        "/api/agent/config", headers={**headers, key: bad}
                    ).status_code,
                    401,
                )
            response = self.client.get("/api/agent/config", headers=headers)
            self.assertEqual(response.status_code, 200)
            verify_desired(response.json(), result["config_verify_key"], node["id"])
            self.post(f"/nodes/{node['id']}/revoke-certificates")
            self.assertEqual(
                self.client.get("/api/agent/config", headers=headers).status_code, 401
            )
            self.assertEqual(
                self.client.get(
                    "/api/agent/config",
                    headers={"Authorization": "Bearer " + node["token"]},
                ).status_code,
                401,
            )

    def test_rotation_overlap_bounded_then_old_cert_fails(self):
        node, token, _, csr = self.setup_node()
        first = self.enroll(node, token, csr).json()
        old = self.trusted_headers(first["certificate"])
        _, next_csr = certificate_request()
        with patch.dict(os.environ, {"DONINO_PROXY_KEY": old["X-Donino-Proxy-Key"]}):
            renewed = self.client.post(
                "/api/agent/renew-certificate", headers=old, json={"csr": next_csr}
            )
            self.assertEqual(renewed.status_code, 200)
            new = self.trusted_headers(renewed.json()["certificate"])
            self.assertEqual(
                self.client.get("/api/agent/config", headers=old).status_code, 200
            )
            with database() as db:
                db.execute(
                    "UPDATE node_certificates SET grace_until=1 WHERE grace_until IS NOT NULL"
                )
            self.assertEqual(
                self.client.get("/api/agent/config", headers=old).status_code, 401
            )
            self.assertEqual(
                self.client.get("/api/agent/config", headers=new).status_code, 200
            )
            self.assertEqual(
                self.client.get(
                    "/api/agent/config",
                    headers={
                        **old,
                        "X-Donino-Client-Cert": new["X-Donino-Client-Cert"],
                    },
                ).status_code,
                200,
            )

    def test_enrollment_expiry_wrong_node_lockout_and_owner_only(self):
        node, token, _, csr = self.setup_node()
        viewer = TestClient(app)
        self.login("viewer", client=viewer)
        self.assertEqual(
            viewer.post(
                f"/api/nodes/{node['id']}/enrollment", headers=self.headers
            ).status_code,
            403,
        )
        with database() as db:
            db.execute("UPDATE node_enrollments SET expires=1")
        self.assertEqual(self.enroll(node, token, csr).status_code, 401)
        for _ in range(9):
            self.assertEqual(self.enroll(node, token, csr).status_code, 401)
        self.assertEqual(self.enroll(node, token, csr).status_code, 429)

    def test_signed_config_tamper_identity_expiry_sequence_and_state_binding(self):
        material = public_material()
        payload = {
            "node_id": "node",
            "revision": "one",
            "config": {"inbounds": []},
            "periods": {},
        }
        envelope = sign_desired(payload, sequence=8, now=1000)
        verify_desired(
            envelope, material["config_verify_key"], "node", sequence=8, now=1001
        )
        for change in (
            {"node_id": "other"},
            {"config": {}},
            {"valid_until": 999999},
            {"sequence": 100},
        ):
            with self.assertRaises(ValueError):
                verify_desired(
                    {**envelope, **change},
                    material["config_verify_key"],
                    "node",
                    now=1001,
                )
        for node_id, sequence, now in (
            ("other", 0, 1001),
            ("node", 9, 1001),
            ("node", 0, 1060),
            ("node", 0, 990),
        ):
            with self.assertRaises(ValueError):
                verify_desired(
                    envelope,
                    material["config_verify_key"],
                    node_id,
                    sequence=sequence,
                    now=now,
                )
