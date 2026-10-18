import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_accounts import PanelBase
from test_tunnel_bridge import preview_body
from app.tunnel_bridge import TunnelClient

SOURCE = os.environ.get("DONINO_TEST_TUNNEL_SOURCE", "")
PIN = "4c19214598d32bd2868f9f46030d8a5dbd494d97"


@unittest.skipUnless(
    SOURCE, "Set DONINO_TEST_TUNNEL_SOURCE to pinned Donino Tunnel checkout"
)
class TunnelContractTest(PanelBase):
    def test_real_worker_unix_contract_builds_private_two_node_plan(self):
        actual = subprocess.check_output(
            ["git", "-C", SOURCE, "rev-parse", "HEAD"], text=True
        ).strip()
        self.assertEqual(actual, PIN)
        root = Path(self.tmp.name)
        log = (root / "fixture.log").open("w")
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("tunnel_worker_fixture.py")),
                str(root),
            ],
            stdout=log,
            stderr=log,
        )
        try:
            for _ in range(100):
                if (root / "ready").exists():
                    break
                if process.poll() is not None:
                    self.fail("Worker fixture failed; inspect private fixture log")
                time.sleep(0.05)
            self.assertTrue((root / "ready").exists())
            os.environ["DONINO_TUNNEL_BRIDGE"] = "1"
            client = TunnelClient(root / "worker.sock", require_root=False)
            with patch("app.tunnel_api.TunnelClient", return_value=client):
                state = self.client.get("/api/tunnels/state")
                self.assertEqual(state.status_code, 200, state.text)
                self.assertTrue(state.json()["available"])
                self.assertNotIn("private-fixture-token", state.text)
                result = self.post("/tunnels/preview", preview_body())
                self.assertEqual(result.status_code, 201, result.text)
                plan = result.json()
                self.assertEqual(plan["summary"]["foreign"], "198.51.100.20")
                self.assertEqual(plan["summary"]["transports"], ["frp-wss", "frp-quic"])
                directory = root / "control/plans" / plan["id"]
                iran = json.loads((directory / "iran/node.json").read_text())
                foreign = json.loads((directory / "foreign/node.json").read_text())
                self.assertEqual(foreign["targets"]["vpn"], "127.0.0.1:8443")
                self.assertEqual(iran["services"][0]["listen"], "0.0.0.0:443")
                self.assertEqual(len(iran["paths"]), 2)
                self.assertNotIn(iran["health_key"], result.text)
                self.assertNotIn("PRIVATE KEY", result.text)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertTrue((directory / "ca/server.key").is_file())
                # Invalid IDs never become shell commands or arbitrary filenames.
                bad = self.post(
                    "/tunnels/start", {"plan_id": "../other", "confirm_replace": True}
                )
                self.assertEqual(bad.status_code, 422)
        finally:
            process.terminate()
            process.wait(timeout=10)
            log.close()
