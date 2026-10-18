import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import tunnel_monitor as native
from ops.common import InstallError
from ops.install import arguments


class MonitorInstallerTest(unittest.TestCase):
    def test_opt_in_preservation_and_preflight_configuration_before_service_actions(
        self,
    ):
        args = arguments([])
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "panel.env"
            self.assertFalse(native.options(args, {}, config))
            self.assertFalse(
                native.options(
                    arguments(["--without-tunnel-monitor"]),
                    {"tunnel_monitor": True},
                    config,
                )
            )
            args = arguments(["--with-tunnel-monitor"])
            with self.assertRaises(InstallError):
                native.options(args, {}, config)
            binary = Path(folder) / "mihomo"
            binary.write_text("fixture, never executed")
            binary.chmod(0o755)
            values = {
                "DONINO_TUNNEL_BRIDGE": "1",
                "DONINO_TUNNEL_PROBE_MIHOMO": str(binary),
                "DONINO_TUNNEL_PROBE_URL": "https://probe.example/check",
                "DONINO_TUNNEL_PROBE_SHA256": "a" * 64,
            }
            config.write_text("".join(k + "=" + v + "\n" for k, v in values.items()))
            unit = Path(folder) / "monitor.service"
            original = dict(os.environ)
            result = subprocess.CompletedProcess([], 0, b"Mihomo v1.19.32", b"")
            with (
                patch.object(native, "UNIT", unit),
                patch("ops.tunnel_monitor.grp.getgrnam"),
                patch("ops.tunnel_monitor.subprocess.run", return_value=result) as run,
            ):
                self.assertTrue(native.options(args, {}, config))
                self.assertTrue(
                    native.options(arguments([]), {"tunnel_monitor": True}, config)
                )
                self.assertEqual(os.environ, original)
                for call in run.call_args_list:
                    self.assertEqual(call.args[0][:3], ["runuser", "-u", "donino"])
                    self.assertNotIn("systemctl", call.args[0])
                unit.write_text("unmanaged fixture")
                with self.assertRaises(InstallError):
                    native.options(args, {}, config)
                state = {
                    "tunnel_monitor": True,
                    "managed_files": {
                        str(unit): hashlib.sha256(unit.read_bytes()).hexdigest()
                    },
                }
                self.assertTrue(native.options(arguments([]), state, config))
                values["DONINO_TUNNEL_PROBE_SHA256"] = "invalid"
                config.write_text(
                    "".join(k + "=" + v + "\n" for k, v in values.items())
                )
                before = run.call_count
                with self.assertRaises(InstallError):
                    native.options(args, state, config)
                self.assertEqual(run.call_count, before)
                self.assertEqual(os.environ, original)

    def test_independent_exit_refuses_control_monitor_flag(self):
        from ops.exit_install import main

        with self.assertRaises(InstallError):
            main(arguments(["plan", "--role", "smart-exit", "--with-tunnel-monitor"]))
