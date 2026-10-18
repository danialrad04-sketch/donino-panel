"""Real loopback carriers + panel node Xray + client Mihomo; no real VPS."""

import copy
import hashlib
import json
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from app import tunnel_probe
from app.db import database
from test_mihomo import _fixture
from test_xray_transports import _free_port

BODY = b"donino-vpn-tunnel-acceptance" * 256
SOURCE = os.environ.get("DONINO_TEST_TUNNEL_SOURCE", "")
PIN = "4c19214598d32bd2868f9f46030d8a5dbd494d97"


class _HTTPS(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


@unittest.skipUnless(
    SOURCE
    and os.environ.get("DONINO_TEST_FRP_DIR")
    and os.environ.get("DONINO_TEST_XRAY")
    and os.environ.get("DONINO_TEST_MIHOMO"),
    "Set pinned tunnel source, FRP, Xray and Mihomo for real-carrier VPN acceptance",
)
class TunnelVPNTest(unittest.TestCase):
    def test_six_tls_profiles_real_wss_quic_failover_restart_and_fail_closed_publication(
        self,
    ):
        self.assertEqual(
            subprocess.check_output(
                ["git", "-C", SOURCE, "rev-parse", "HEAD"], text=True
            ).strip(),
            PIN,
        )
        for binary in ("frpc", "frps"):
            self.assertEqual(
                subprocess.check_output(
                    [str(Path(os.environ["DONINO_TEST_FRP_DIR"]) / binary), "-v"],
                    text=True,
                ).strip(),
                "0.71.0",
            )
        sys.path.insert(0, SOURCE)
        from donino_link.plan import make_plan
        from donino_link.config import atomic_json

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            processes = []
            with _fixture(
                os.environ["DONINO_TEST_XRAY"],
                os.environ["DONINO_TEST_MIHOMO"],
                root,
                processes,
            ) as lab:
                os.environ["DONINO_TUNNEL_BRIDGE"] = "1"
                os.environ["DONINO_TUNNEL_MONITOR"] = "1"
                https = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPS)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(
                    root / "pki/server.pem", root / "pki/server.key"
                )
                https.socket = context.wrap_socket(https.socket, server_side=True)
                thread = threading.Thread(target=https.serve_forever, daemon=True)
                thread.start()
                os.environ.update(
                    DONINO_TUNNEL_PROBE_MIHOMO=os.environ["DONINO_TEST_MIHOMO"],
                    DONINO_TUNNEL_PROBE_URL=f"https://localhost:{https.server_port}/acceptance",
                    DONINO_TUNNEL_PROBE_SHA256=hashlib.sha256(BODY).hexdigest(),
                    DONINO_TUNNEL_PROBE_CA=str(root / "pki/ca.pem"),
                )
                plan = root / "plan"
                worker = None
                log = (root / "carrier.log").open("w")
                try:
                    user = lab.new_user("tunnel-acceptance")
                    lab.agent.tick()
                    inbounds = lab.panel.get("/api/inbounds").json()
                    node_id = inbounds[0]["node_id"]
                    # Two roles use distinct loopback ports in one namespace.
                    # Low unprivileged blocks avoid the OS ephemeral range.
                    public = 17000 + _free_port() % 1000
                    services = [
                        {"inbound_id": row["id"], "listen_port": public + i}
                        for i, row in enumerate(inbounds)
                    ]
                    state = {
                        "available": True,
                        "busy": False,
                        "profiles": [
                            {
                                "id": "a" * 32,
                                "name": "lab",
                                "host": "127.0.0.1",
                                "management": "https-v1",
                            }
                        ],
                        "jobs": [],
                    }

                    def controller(method, route, body=None):
                        nonlocal worker
                        if route == "/state":
                            return copy.deepcopy(state)
                        if route == "/preview":
                            make_plan(
                                plan,
                                body["iran"],
                                "127.0.0.1",
                                body["services"],
                                body["transports"],
                                "fixture-only-password-123",
                                True,
                                base=21000,
                                carrier_base=25000,
                                health_port=19091,
                            )
                            summary = json.loads((plan / "plan.json").read_text())
                            return {
                                "id": "b" * 32,
                                "expires_at": time.time() + 3600,
                                "summary": summary,
                            }
                        if route == "/start":
                            worker = subprocess.Popen(
                                [
                                    sys.executable,
                                    str(
                                        Path(__file__).with_name(
                                            "tunnel_carrier_fixture.py"
                                        )
                                    ),
                                    str(plan),
                                ],
                                stdout=log,
                                stderr=log,
                                start_new_session=True,
                            )
                            deadline = time.monotonic() + 25
                            while not (plan / "ready").exists():
                                if (
                                    worker.poll() is not None
                                    or time.monotonic() > deadline
                                ):
                                    raise AssertionError(
                                        "Carrier runtime failed: "
                                        + (root / "carrier.log").read_text()[-2000:]
                                    )
                                time.sleep(0.05)
                            now = time.time()
                            job = {
                                "id": "c" * 32,
                                "plan_id": body["plan_id"],
                                "status": "succeeded",
                                "stage": "lab-ready",
                                "created": now,
                                "updated": now,
                            }
                            state["jobs"] = [job]
                            return job
                        raise AssertionError("Unexpected fixture route")

                    with patch("app.tunnel_api.call", side_effect=controller):
                        response = lab.panel.post(
                            "/api/tunnels/bindings",
                            json={
                                "node_id": node_id,
                                "profile_id": "a" * 32,
                                "iran": "127.0.0.1",
                                "services": services,
                                "transports": ["frp-wss", "frp-quic"],
                            },
                        )
                        self.assertEqual(response.status_code, 201, response.text)
                        binding = response.json()
                        path = f"/api/tunnels/bindings/{binding['id']}"
                        response = lab.panel.post(
                            path + "/start", json={"confirm_replace": True}
                        )
                        self.assertEqual(response.status_code, 202, response.text)
                        request = {
                            "device_id": user["id"],
                            "inbound_ids": [row["id"] for row in inbounds],
                        }

                        def verify_success():
                            result = lab.panel.post(path + "/verify", json=request)
                            self.assertEqual(result.status_code, 201, result.text)
                            self.assertEqual(
                                result.json()["phase"], "succeeded", result.text
                            )
                            result = lab.panel.post(
                                path + "/publication",
                                json={
                                    "check_id": result.json()["id"],
                                    "confirm_publish": True,
                                },
                            )
                            self.assertEqual(result.status_code, 200, result.text)
                            entries = lab.clash(lab.token(user["id"]))["proxies"]
                            self.assertEqual(len(entries), 12)
                            return [
                                p
                                for p in entries
                                if p["port"] in {s["listen_port"] for s in services}
                            ]

                        def observed():
                            return json.loads((plan / "observed.json").read_text())

                        def command(action, carrier, expect=None):
                            atomic_json(
                                plan / "command.json",
                                {"action": action, "carrier": carrier},
                            )
                            deadline = time.monotonic() + 12
                            while (plan / "command.json").exists() or (
                                expect is not None
                                and observed()["healthy"][carrier] != expect
                            ):
                                self.assertLess(
                                    time.monotonic(),
                                    deadline,
                                    "Carrier state did not converge",
                                )
                                time.sleep(0.05)

                        relay_profiles = verify_success()
                        self.assertEqual(len(relay_profiles), 6)
                        from app import tunnel_monitor as monitor

                        instance = "real-carrier-scheduler"
                        self.assertTrue(monitor.heartbeat(instance))
                        with database() as db:
                            check_id = db.execute(
                                "SELECT check_id FROM tunnel_endpoints LIMIT 1"
                            ).fetchone()[0]
                        result = lab.panel.put(
                            path + "/monitor",
                            json={"check_id": check_id, "confirm_auto_renew": True},
                        )
                        self.assertEqual(result.status_code, 200, result.text)

                        def automatic(expected):
                            monitor.heartbeat(instance)
                            with database() as db:
                                db.execute("UPDATE tunnel_monitors SET next_run=1")
                            self.assertTrue(monitor.run_due(instance, controller))
                            status = lab.panel.get(path).json()["monitor"]
                            self.assertEqual(status["phase"], expected, status)
                            entries = lab.clash(lab.token(user["id"]))["proxies"]
                            self.assertEqual(
                                len(entries), 12 if expected == "healthy" else 6
                            )
                            return [
                                p
                                for p in entries
                                if p["port"] in {s["listen_port"] for s in services}
                            ]

                        self.assertEqual(observed()["selected"], "frp-wss")
                        deadline = time.monotonic() + 3
                        while True:
                            lab.agent.tick()
                            with database() as db:
                                used = db.execute(
                                    "SELECT used FROM users WHERE id=?", (user["id"],)
                                ).fetchone()[0]
                            if used or time.monotonic() >= deadline:
                                break
                            time.sleep(0.1)
                        with database() as db:
                            self.assertGreater(
                                db.execute(
                                    "SELECT used FROM users WHERE id=?", (user["id"],)
                                ).fetchone()[0],
                                0,
                            )
                            self.assertGreater(
                                db.execute(
                                    "SELECT uploaded+downloaded FROM devices WHERE id=?",
                                    (user["id"],),
                                ).fetchone()[0],
                                0,
                            )
                        print(
                            "Six real TLS VPN profiles crossed FRP WSS; accounting reached the original device"
                        )

                        command("stop", "frp-wss", False)
                        automatic("healthy")
                        self.assertEqual(observed()["selected"], "frp-quic")
                        print(
                            "WSS carrier loss: all six VPN profiles transferred over real QUIC"
                        )
                        command("start", "frp-wss", True)
                        command("prefer", "frp-wss")
                        relay_profiles = automatic("healthy")
                        self.assertEqual(observed()["selected"], "frp-wss")
                        print(
                            "Restarted WSS carrier: real-client monitor renewed the consented publication"
                        )

                        # Exercise the production verifier's TLS rejection too.
                        bad = dict(relay_profiles[0])
                        bad["sni" if bad["type"] == "trojan" else "servername"] = (
                            "wrong.example"
                        )
                        with self.assertRaises(tunnel_probe.ProbeError):
                            tunnel_probe.run([bad])

                        command("stop", "frp-wss", False)
                        command("stop", "frp-quic", False)
                        automatic("unhealthy")
                        refused = lab.panel.post(
                            path + "/publication",
                            json={
                                "check_id": check_id,
                                "confirm_publish": True,
                            },
                        )
                        self.assertEqual(refused.status_code, 409)
                        self.assertEqual(
                            len(lab.clash(lab.token(user["id"]))["proxies"]), 6
                        )
                        print(
                            "Both real carriers stopped: automatic withdrawal and old-proof publication refusal succeeded"
                        )
                        command("start", "frp-quic", True)
                        automatic("healthy")
                        self.assertEqual(observed()["selected"], "frp-quic")
                        print(
                            "QUIC recovery: real-client monitor restored only the original six consented endpoints"
                        )
                finally:
                    if worker:
                        worker.terminate()
                        try:
                            worker.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            worker.kill()
                            worker.wait(timeout=3)
                        finally:
                            try:
                                os.killpg(worker.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    log.close()
                    https.shutdown()
                    https.server_close()
                    thread.join(timeout=2)
