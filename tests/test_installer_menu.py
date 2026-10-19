import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.common import InstallError
from ops.install import Installer, arguments, nginx_config
from ops.menu import run_menu
from ops.preflight import domain_name


class FakeTTY:
    def __init__(self, inputs):
        self.inputs = iter(inputs)
        self.output = io.StringIO()

    def write(self, value):
        return self.output.write(value)

    def flush(self):
        pass

    def readline(self):
        return next(self.inputs, "")


class InstallerMenuTest(unittest.TestCase):
    def test_wizard_http_and_screen_restore_without_shell(self):
        tty = FakeTTY(["1\n", "203.0.113.9\n", "y\n", "\n", "0\n"])
        calls = []
        with patch.dict(os.environ, TERM="xterm-256color"):
            self.assertEqual(
                run_menu(
                    tty,
                    execute=lambda args: calls.append(args) or 0,
                    read_state=lambda: {},
                    upgrade=lambda _: 1,
                ),
                0,
            )
        self.assertEqual(
            calls, [["install", "--domain", "203.0.113.9", "--tls", "none"]]
        )
        text = tty.output.getvalue()
        self.assertIn("\033[?1049h", text)
        self.assertTrue(text.endswith("\033[?1049l"))
        self.assertIn("HTTP sends login", text)

    def test_cancel_and_invalid_input_never_start_host_actions(self):
        tty = FakeTTY(
            ["1\n", "host;sh\n", "\n", "2\n", "panel.example.com\n", "\n", "n\n", "0\n"]
        )
        with patch.dict(os.environ, TERM="xterm"):
            self.assertEqual(
                run_menu(
                    tty,
                    execute=lambda _: self.fail("Unconfirmed host action"),
                    read_state=lambda: {},
                    upgrade=lambda _: self.fail("Unconfirmed upgrade"),
                ),
                0,
            )
        self.assertTrue(tty.output.getvalue().endswith("\033[?1049l"))
        self.assertEqual(domain_name("127.0.0.1", allow_ip=True), "127.0.0.1")
        with self.assertRaises(InstallError):
            domain_name("127.0.0.1")
        config = nginx_config("127.0.0.1", plain=True)
        self.assertIn("listen 80;", config)
        self.assertNotIn("ssl_certificate", config)
        self.assertNotIn("return 301", config)

    def test_http_repair_preserves_mode_without_any_certificate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / "release"
            release.mkdir()
            current = root / "current"
            current.symlink_to(release)
            state = root / "state.json"
            state.write_text(
                json.dumps({"domain": "127.0.0.1", "tls_mode": "none", "completed": []})
            )
            with (
                patch("ops.install.STATE", state),
                patch("ops.install.CURRENT", current),
                patch("ops.install.CONFIG", root / "config"),
                patch("ops.install.run"),
                patch(
                    "ops.install.validate_certificate",
                    side_effect=AssertionError("HTTP must not read a certificate"),
                ),
            ):
                obj = Installer(arguments(["repair", "--tls", "none"]))
                with patch.object(obj, "proxy") as proxy, patch.object(obj, "health"):
                    obj.repair()
                proxy.assert_called_once_with("127.0.0.1", tls=False, plain=True)

    def test_legacy_existing_tls_upgrade_passes_preflight_without_assuming_acme(self):
        class StopBeforePackages(Exception):
            pass

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state.json"
            state.write_text(
                json.dumps({"domain": "panel.example.com", "completed": []})
            )
            args = arguments(
                [
                    "install",
                    "--domain",
                    "panel.example.com",
                    "--tls",
                    "existing",
                    "--cert-file",
                    "/fixture.crt",
                    "--key-file",
                    "/fixture.key",
                ]
            )
            with (
                patch("ops.install.STATE", state),
                patch(
                    "ops.install.inspect",
                    return_value={
                        "domain": "panel.example.com",
                        "ipv6": False,
                        "errors": [],
                    },
                ),
                patch("ops.install.verify_manifest"),
                patch("ops.install.validate_certificate"),
                patch("ops.install.CONFIG", root / "config"),
            ):
                obj = Installer(args)
                with patch.object(obj, "packages", side_effect=StopBeforePackages):
                    with self.assertRaises(StopBeforePackages):
                        obj.install()
            saved = json.loads(state.read_text())
            self.assertEqual(saved["tls_mode"], "existing")
