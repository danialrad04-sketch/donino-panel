import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from test_accounts import PanelBase
from app.db import database
from app.tunnel_bridge import BridgeError, PreviewInput, TunnelClient


def preview_body():
    return {
        "profile_id": "a" * 32,
        "iran": "192.0.2.10",
        "services": [{"id": "vpn", "listen_port": 443, "target_port": 8443}],
        "transports": ["frp-wss", "frp-quic"],
    }


class TunnelBridgeTest(PanelBase):
    def test_opt_in_and_owner_boundary_prevent_worker_calls(self):
        os.environ.pop("DONINO_TUNNEL_BRIDGE", None)
        with patch("app.tunnel_api.TunnelClient") as worker:
            self.assertFalse(self.client.get("/api/tunnels/state").json()["enabled"])
            self.assertEqual(
                self.post("/tunnels/preview", preview_body()).status_code, 503
            )
            for role in ("operator", "viewer"):
                self.login(role)
                self.assertEqual(self.client.get("/api/tunnels/state").status_code, 403)
                self.assertEqual(
                    self.post("/tunnels/preview", preview_body()).status_code, 403
                )
            worker.assert_not_called()

    def test_typed_spec_and_no_command_path_udp_or_experimental_input(self):
        spec = PreviewInput.model_validate(preview_body()).worker_spec()
        self.assertEqual(
            spec["services"],
            [
                {
                    "id": "vpn",
                    "listen": "0.0.0.0:443",
                    "target": "127.0.0.1:8443",
                    "protocol": "tcp",
                }
            ],
        )
        self.assertFalse(spec["experimental"])
        self.assertFalse(spec["open_ufw"])
        for change in (
            {"command": "echo unwanted"},
            {"socket": "/tmp/untrusted"},
            {"transports": ["paqet"]},
            {"transports": ["frp-wss", "frp-wss"]},
            {"services": [{"id": "x", "listen_port": True, "target_port": 8443}]},
            {"iran": "https://example.com"},
        ):
            self.assertEqual(
                self.post("/tunnels/preview", {**preview_body(), **change}).status_code,
                422,
            )
        self.assertEqual(
            self.post(
                "/tunnels/start", {"plan_id": "a" * 32, "confirm_replace": False}
            ).status_code,
            422,
        )
        self.assertEqual(
            self.post(
                "/tunnels/start", {"plan_id": "a" * 32, "confirm_replace": 1}
            ).status_code,
            422,
        )
        secret = "do-not-echo-this-invalid-pair-code"
        result = self.post(
            "/tunnels/pair", {"name": "foreign", "host": "example.com", "code": secret}
        )
        self.assertEqual(result.status_code, 422)
        self.assertNotIn(secret, result.text)

    def test_response_whitelist_and_audit_never_include_worker_secrets(self):
        os.environ["DONINO_TUNNEL_BRIDGE"] = "1"
        upstream = {
            "available": True,
            "busy": False,
            "profiles": [
                {
                    "id": "a" * 32,
                    "name": "foreign",
                    "host": "198.51.100.20",
                    "agent_token": "DO-NOT-EXPOSE",
                    "management": "https-v1",
                }
            ],
            "jobs": [],
            "active_spec": {"health_key": "DO-NOT-EXPOSE"},
            "inventory": {"private": "DO-NOT-EXPOSE"},
        }
        with patch("app.tunnel_api.TunnelClient.request", return_value=upstream):
            result = self.client.get("/api/tunnels/state")
            self.assertEqual(result.status_code, 200, result.text)
            self.assertNotIn("DO-NOT-EXPOSE", result.text)
        with patch(
            "app.tunnel_api.TunnelClient.request", return_value=upstream["profiles"][0]
        ):
            pair = self.post(
                "/tunnels/pair",
                {
                    "name": "foreign",
                    "host": "198.51.100.20",
                    "code": "donino1." + "b" * 64 + "." + "c" * 43,
                },
            )
            self.assertEqual(pair.status_code, 201, pair.text)
            self.assertNotIn("DO-NOT-EXPOSE", pair.text)
        with database() as db:
            rows = [
                dict(row)
                for row in db.execute("SELECT * FROM audit WHERE action='tunnel.pair'")
            ]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("donino1", json.dumps(rows))

    def test_socket_ownership_and_no_automatic_retry_on_uncertain_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "socket"
            path.write_text("not a socket")
            with self.assertRaises(BridgeError):
                TunnelClient(path).check_socket()
        for uid, mode in (
            (1000, stat.S_IFSOCK | 0o660),
            (0, stat.S_IFSOCK | 0o666),
            (0, stat.S_IFLNK | 0o660),
        ):
            with patch.object(
                Path, "lstat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)
            ):
                with self.assertRaises(BridgeError):
                    TunnelClient().check_socket()
        os.environ["DONINO_TUNNEL_BRIDGE"] = "1"
        with patch(
            "app.tunnel_api.TunnelClient.request", side_effect=BridgeError(502)
        ) as request:
            result = self.post(
                "/tunnels/start", {"plan_id": "a" * 32, "confirm_replace": True}
            )
            self.assertEqual(result.status_code, 502)
            self.assertEqual(request.call_count, 1)


class TunnelTransportTest(unittest.TestCase):
    def test_upstream_redirect_large_response_invalid_json_and_timeout_are_redacted(
        self,
    ):
        responses = [
            httpx.Response(302, headers={"Location": "https://unexpected.example"}),
            httpx.Response(200, content=b"x" * (2 * 1024 * 1024 + 1)),
            httpx.Response(200, content=b"private-invalid-json"),
            httpx.Response(400, json={"error": "private-upstream-token"}),
            httpx.Response(200, json=[]),
        ]
        for response in responses:
            seen = []

            def reply(request):
                seen.append(request)
                return response

            with (
                patch.object(TunnelClient, "check_socket"),
                patch(
                    "app.tunnel_bridge.httpx.HTTPTransport",
                    return_value=httpx.MockTransport(reply),
                ),
            ):
                with self.assertRaises(BridgeError) as error:
                    TunnelClient().request("POST", "/start", {"plan_id": "a" * 32})
                self.assertNotIn("private", str(error.exception))
                self.assertEqual(len(seen), 1)
        with (
            patch.object(TunnelClient, "check_socket"),
            patch(
                "app.tunnel_bridge.httpx.HTTPTransport",
                return_value=httpx.MockTransport(
                    lambda _: (_ for _ in ()).throw(httpx.ReadTimeout("private-token"))
                ),
            ),
        ):
            with self.assertRaises(BridgeError) as error:
                TunnelClient().request("GET", "/state")
            self.assertNotIn("private", str(error.exception))
