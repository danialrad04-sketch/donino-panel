import os
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from agent.main import NodeAgent
from agent.live import user_additions


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_PANEL_URL": "https://panel.example.com",
                "DONINO_NODE_TOKEN": "test-token",
                "DONINO_NODE_STATE": self.tmp.name,
                "DONINO_XRAY": "/unused/xray",
            },
        )
        self.env.start()
        self.agent = NodeAgent()
        self.running = Mock()
        self.running.poll.return_value = None
        self.agent.proc = self.running
        self.agent.revision = "old-revision"

    def tearDown(self):
        self.agent.close()
        self.env.stop()
        self.tmp.cleanup()

    def desired(self):
        return {
            "revision": "new-revision",
            "config": {
                "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 10085}]
            },
        }

    def test_remote_plain_http_refused(self):
        with patch.dict(os.environ, {"DONINO_PANEL_URL": "http://panel.example.com"}):
            with self.assertRaises(ValueError):
                NodeAgent()

    def test_public_stats_bind_refused(self):
        desired = self.desired()
        desired["config"]["inbounds"][0]["listen"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            self.agent.apply(desired)
        self.running.terminate.assert_not_called()

    def test_invalid_config_keeps_running_core(self):
        with patch("agent.main.subprocess.run", return_value=Mock(returncode=23)):
            with self.assertRaises(ValueError):
                self.agent.apply(self.desired())
        self.running.terminate.assert_not_called()
        self.assertEqual(self.agent.revision, "old-revision")
        self.assertFalse((Path(self.tmp.name) / "config.json").exists())

    def test_failed_final_report_keeps_running_core(self):
        with (
            patch("agent.main.subprocess.run", return_value=Mock(returncode=0)),
            patch.object(
                self.agent, "report", side_effect=httpx.ConnectError("unavailable")
            ),
        ):
            with self.assertRaises(httpx.ConnectError):
                self.agent.apply(self.desired())
        self.running.terminate.assert_not_called()
        self.assertEqual(self.agent.revision, "old-revision")

    def config(self):
        return {
            "inbounds": [
                {"tag": "api", "listen": "127.0.0.1", "port": 10085},
                {
                    "tag": "inbound",
                    "protocol": "vless",
                    "port": 443,
                    "settings": {"clients": [{"email": "old", "id": "secret"}]},
                },
            ]
        }

    def test_live_update_never_handles_revocation_or_transport_changes(self):
        before = self.config()
        add = copy.deepcopy(before)
        add["inbounds"][1]["settings"]["clients"].append(
            {"email": "new", "id": "new-secret"}
        )
        self.assertEqual(len(user_additions(before, add)), 1)
        self.assertIsNone(user_additions(add, before))
        changed = copy.deepcopy(before)
        changed["inbounds"][1]["port"] = 8443
        self.assertIsNone(user_additions(before, changed))
        rotated = copy.deepcopy(before)
        rotated["inbounds"][1]["settings"]["clients"][0]["id"] = "rotated"
        self.assertIsNone(user_additions(before, rotated))

    def test_partial_cli_success_is_not_accepted(self):
        with patch(
            "agent.main.subprocess.run",
            return_value=Mock(returncode=0, stdout="Added 0 user(s) in total."),
        ):
            with self.assertRaises(RuntimeError):
                self.agent.api_command("adu", ["file.json"], 1)

    def test_startup_failure_restores_previous_core_and_revision(self):
        old = self.config()
        desired = copy.deepcopy(old)
        desired["inbounds"][1]["port"] = 8443
        self.agent.config = old

        def start(config):
            if config == desired:
                raise RuntimeError("port in use")
            self.agent.proc = self.running

        with (
            patch.object(self.agent, "report"),
            patch("agent.main.subprocess.run", return_value=Mock(returncode=0)),
            patch.object(self.agent, "start_core", side_effect=start),
        ):
            with self.assertRaisesRegex(RuntimeError, "restored previous"):
                self.agent.apply({"revision": "desired", "config": desired})
        self.assertTrue(self.agent.running())
        self.assertEqual(self.agent.config, old)
        self.assertEqual(self.agent.revision, "old-revision")
        self.assertEqual(self.agent.apply_mode, "rollback")

    def test_only_one_agent_owns_a_state_directory(self):
        with self.assertRaisesRegex(RuntimeError, "Another Donino agent"):
            NodeAgent()

    def test_period_change_forces_restart_with_same_transport_and_credentials(self):
        current = self.config()
        self.agent.config = copy.deepcopy(current)
        self.agent.periods = {"old": 0}
        with (
            patch.object(self.agent, "report"),
            patch("agent.main.subprocess.run", return_value=Mock(returncode=0)),
            patch.object(self.agent, "start_core") as start,
            patch.object(self.agent, "hot_apply") as hot,
        ):
            self.agent.apply(
                {"revision": "new-period", "config": current, "periods": {"old": 1}}
            )
        start.assert_called_once()
        hot.assert_not_called()
        self.assertEqual(self.agent.periods, {"old": 1})


if __name__ == "__main__":
    unittest.main()
