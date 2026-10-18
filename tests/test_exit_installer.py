import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import exit_install, releases
from ops.common import InstallError
from ops.install import arguments, main
from ops.manifest import write_manifest
from ops.tls import install_certificate
from test_xray_transports import _write_test_pki


class ExitInstallerTest(unittest.TestCase):
    def test_acme_uses_dedicated_webroot_and_certificate_identity(self):
        args = arguments(["--role", "smart-exit", "--tls", "acme", "--acme-staging"])
        instance = exit_install.ExitInstaller.__new__(exit_install.ExitInstaller)
        instance.args, instance.state = args, {"domain": "exit.example.com"}
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(exit_install, "CONFIG", Path(folder)),
            patch.object(exit_install.Path, "mkdir"),
            patch.object(instance, "proxy") as proxy,
            patch.object(instance, "checkpoint"),
            patch.object(exit_install, "run") as run,
            patch.object(exit_install, "install_certificate") as certificate,
        ):
            instance.certificate()
            command = run.call_args.args[0]
            self.assertIn("--webroot", command)
            self.assertIn("/var/lib/donino-exit-acme", command)
            self.assertIn("donino-smart-exit", command)
            self.assertIn("--staging", command)
            self.assertEqual(command[command.index("-d") + 1], "exit.example.com")
            self.assertEqual(certificate.call_args.args[0], "exit.example.com")
            proxy.assert_called_once()

    def test_renewal_failed_readiness_restores_root_and_worker_certificate_pair(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ca1, cert1, key1 = _write_test_pki(root / "one", ("exit.example.com",))
            ca2, cert2, key2 = _write_test_pki(
                root / "two",
                ("exit.example.com",),
                authority_name="Donino renewal test CA",
            )
            config = root / "config"
            config.mkdir()
            (config / "ca.pem").write_bytes(ca1.read_bytes() + ca2.read_bytes())
            install_certificate(
                "exit.example.com",
                cert1,
                key1,
                config / "tls",
                ca_file=config / "ca.pem",
            )
            lineage = root / "donino-smart-exit"
            lineage.mkdir()
            shutil.copyfile(cert2, lineage / "fullchain.pem")
            shutil.copyfile(key2, lineage / "privkey.pem")
            current = root / "current"
            current.symlink_to(root / "one", target_is_directory=True)
            instance = exit_install.ExitInstaller.__new__(exit_install.ExitInstaller)
            instance.state = {"domain": "exit.example.com"}
            installed = []

            def fingerprint(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()

            def sync():
                installed.append(
                    (
                        fingerprint(config / "tls/panel.crt"),
                        fingerprint(config / "tls/panel.key"),
                    )
                )

            with (
                patch.object(exit_install, "CONFIG", config),
                patch.object(exit_install, "CURRENT", current),
                patch.dict(os.environ, {"RENEWED_LINEAGE": str(lineage)}),
                patch.object(instance, "sync_tls", side_effect=sync),
                patch.object(
                    instance, "health", side_effect=InstallError("readiness failed")
                ),
                patch.object(exit_install, "run"),
            ):
                with self.assertRaises(InstallError):
                    instance.renew()
            self.assertEqual(
                installed,
                [
                    (fingerprint(cert2), fingerprint(key2)),
                    (fingerprint(cert1), fingerprint(key1)),
                ],
            )
            self.assertEqual(fingerprint(config / "tls/panel.crt"), fingerprint(cert1))
            self.assertEqual(fingerprint(config / "tls/panel.key"), fingerprint(key1))

    def test_role_options_preserve_settings_and_refuse_ambiguous_inputs(self):
        args = arguments(
            [
                "--role",
                "smart-exit",
                "--domain",
                "exit.example.com",
                "--exit-allow-domain",
                "service.example.com",
            ]
        )
        expected = {
            "domain": "exit.example.com",
            "domains": ["service.example.com"],
            "listen": "0.0.0.0",
            "port": 9445,
        }
        self.assertEqual(exit_install.settings(args, {}), expected)
        self.assertEqual(
            exit_install.settings(arguments(["--role", "smart-exit"]), expected),
            expected,
        )
        for flags in (
            ["--exit-port", "80"],
            ["--exit-port", "0"],
            ["--exit-listen", "host.example"],
            ["--exit-allow-domain", "*.example.com"],
            ["--domain", "changed.example.com"],
        ):
            with self.assertRaises(InstallError):
                exit_install.settings(
                    arguments(["--role", "smart-exit", *flags]), expected
                )
        with self.assertRaises(InstallError):
            exit_install.settings(
                arguments(["--role", "smart-exit", "--domain", "exit.example.com"]), {}
            )
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(["plan", "--domain", "exit.example.com", "--exit-port", "9445"]), 2
            )
            self.assertEqual(main(["--role", "smart-exit", "--with-dns"]), 2)

    def test_credentials_are_stable_private_data_and_bad_stored_secrets_are_refused(
        self,
    ):
        config = {"domain": "exit.example.com", "port": 9445}
        first = exit_install.credential(None, config)
        self.assertEqual(exit_install.credential(first, config), first)
        changed = exit_install.credential(first, {**config, "port": 9446})
        self.assertEqual(changed["password"], first["password"])
        self.assertEqual(changed["port"], 9446)
        for bad in (
            {},
            [],
            {"username": "short", "password": "x" * 32},
            {**first, "password": "x" * 20 + "\n"},
        ):
            with self.assertRaises(InstallError):
                exit_install.credential(bad, config)

    def test_lost_private_access_is_not_implicitly_replaced(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(exit_install, "CONFIG", Path(folder)),
        ):
            instance = exit_install.ExitInstaller.__new__(exit_install.ExitInstaller)
            instance.state = {"completed": ["configured", "complete"]}
            with self.assertRaises(InstallError):
                instance.stored_access()
            self.assertFalse((Path(folder) / "gateway-access.json").exists())

    def test_existing_tls_mode_is_preserved_and_plan_has_no_control_database(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "format": "donino-smart-exit-v1",
                        "completed": [],
                        "domain": "exit.example.com",
                        "domains": ["service.example.com"],
                        "tls": "existing",
                    }
                )
            )
            with (
                patch.object(exit_install, "STATE", state),
                patch.object(
                    exit_install, "inspect", return_value={"errors": []}
                ) as inspect,
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        exit_install.main(arguments(["plan", "--role", "smart-exit"])),
                        0,
                    )
                result = json.loads(output.getvalue())
                self.assertIsNone(result["database"])
                self.assertEqual(result["required_public_ports"], ["9445/tcp"])
                self.assertEqual(inspect.call_args.kwargs["ports"], ())
                self.assertNotIn("password", output.getvalue())

    def test_http_failure_rolls_back_file_and_persisted_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state, http = root / "state.json", root / "exit.conf"
            http.write_bytes(b"previous configuration")
            previous = {str(http): hashlib.sha256(http.read_bytes()).hexdigest()}
            instance = exit_install.ExitInstaller.__new__(exit_install.ExitInstaller)
            instance.state = {
                "domain": "exit.example.com",
                "ipv6": False,
                "managed_files": previous.copy(),
            }
            with (
                patch.object(exit_install, "STATE", state),
                patch.object(exit_install, "HTTP", http),
                patch.object(
                    exit_install, "run", side_effect=InstallError("nginx failed")
                ),
            ):
                with self.assertRaises(InstallError):
                    instance.proxy()
            self.assertEqual(http.read_bytes(), b"previous configuration")
            self.assertEqual(json.loads(state.read_text())["managed_files"], previous)

    def test_modified_and_unknown_inventory_is_refused_before_stopping_service(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = [root / name for name in ("http", "unit", "hook")]
            instance = exit_install.ExitInstaller.__new__(exit_install.ExitInstaller)
            paths[1].write_text("managed service")
            instance.state = {
                "managed_files": {
                    str(paths[1]): hashlib.sha256(paths[1].read_bytes()).hexdigest()
                }
            }
            with (
                patch.object(exit_install, "HTTP", paths[0]),
                patch.object(exit_install, "UNIT", paths[1]),
                patch.object(exit_install, "HOOK", paths[2]),
                patch.object(exit_install, "run") as run,
            ):
                paths[1].write_text("operator's local change")
                with self.assertRaises(InstallError):
                    instance.uninstall()
                run.assert_not_called()
                paths[1].write_text("managed service")
                instance.state["managed_files"][str(root / "unknown")] = "a" * 64
                with self.assertRaises(InstallError):
                    instance.uninstall()
                run.assert_not_called()
                self.assertTrue(paths[1].is_file())

    def test_verified_role_release_rejects_modified_immutable_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            for name, content in {
                "app/main.py": "# fixture",
                "app/__init__.py": '__version__="1.0.0a12"',
                "app/db.py": "# fixture",
                "ops/install.py": "# fixture",
                "requirements.txt": "# fixture",
                "requirements.lock": "# fixture",
                "LICENSE": "fixture",
            }.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            write_manifest(source)
            with patch.object(releases, "run") as run:
                release = releases.prepare(source, root / "role")
                self.assertFalse((root / "role/current").exists())
                self.assertNotIn("requirements-postgres.txt", str(run.call_args_list))
                (release / "app/main.py").write_text("# tampered release")
                with self.assertRaises(InstallError):
                    releases.prepare(source, root / "role")


if __name__ == "__main__":
    unittest.main()
