import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import installer


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_domain_validation(self):
        self.assertEqual(installer.validate_domain("Panel.Example.com"), "panel.example.com")
        for bad in ["https://panel.example.com", "localhost", "a b.com", "-x.example.com", "panel.example.com:443", ""]:
            with self.assertRaises(installer.InstallError, msg=bad) as caught:
                installer.validate_domain(bad)
            self.assertEqual(caught.exception.code, 2)

    def test_preflight_rejects_unsupported_os(self):
        (self.root / "etc/os-release").write_text("ID=fedora\nVERSION_ID=40\n")
        with patch("app.installer.socket.gethostbyname_ex", return_value=("x", [], ["203.0.113.5"])):
            with self.assertRaises(installer.InstallError) as caught:
                installer.preflight("panel.example.com", root=str(self.root))
        self.assertEqual(caught.exception.code, 2)

    def test_preflight_dns_mismatch_is_exit_5(self):
        with patch("app.installer.socket.gethostbyname_ex", return_value=("x", [], ["198.51.100.1"])):
            with self.assertRaises(installer.InstallError) as caught:
                installer.preflight("panel.example.com", expected_ip="203.0.113.5", root=str(self.root))
        self.assertEqual(caught.exception.code, 5)

    def test_preflight_missing_dns_is_exit_5(self):
        with patch("app.installer.socket.gethostbyname_ex", side_effect=socket.gaierror()):
            with self.assertRaises(installer.InstallError) as caught:
                installer.preflight("panel.example.com", root=str(self.root))
        self.assertEqual(caught.exception.code, 5)

    def test_preflight_success_on_supported_system(self):
        with patch("app.installer.socket.gethostbyname_ex", return_value=("x", [], ["203.0.113.5"])):
            rows = installer.preflight("panel.example.com", expected_ip="203.0.113.5", root=str(self.root))
        names = {name: level for level, name, _ in rows}
        self.assertEqual(names["os"], "OK")
        self.assertEqual(names["dns"], "OK")

    def test_render_writes_files_with_domain_and_private_env(self):
        result = installer.render("panel.example.com", root=str(self.root))
        self.assertEqual(len(result["written"]), 3)
        env = self.root / "etc/donino/panel.env"
        self.assertEqual(oct(os.stat(env).st_mode & 0o777), "0o600")
        self.assertIn("DONINO_PUBLIC_URL=https://panel.example.com", env.read_text())
        vhost = (self.root / "etc/nginx/sites-available/donino-panel.conf").read_text()
        self.assertIn("server_name panel.example.com;", vhost)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;", vhost)

    def test_render_is_idempotent(self):
        installer.render("panel.example.com", root=str(self.root))
        second = installer.render("panel.example.com", root=str(self.root))
        self.assertEqual(second["written"], [])
        self.assertEqual(len(second["unchanged"]), 3)

    def test_render_refuses_to_overwrite_different_content(self):
        target = self.root / "etc/donino/panel.env"
        target.parent.mkdir(parents=True)
        target.write_text("DONINO_DB=/somewhere/else.db\n")
        with self.assertRaises(installer.InstallError) as caught:
            installer.render("panel.example.com", root=str(self.root))
        self.assertEqual(caught.exception.code, 7)
        self.assertEqual(target.read_text(), "DONINO_DB=/somewhere/else.db\n")
        # Nothing else was written: the check runs before any file is created.
        self.assertFalse((self.root / "etc/systemd/system/donino-panel.service").exists())

    def test_held_lock_is_exit_7(self):
        lock_path = self.root / "run/donino-install.lock"
        lock_path.parent.mkdir(parents=True)
        with open(lock_path, "w") as holder:
            import fcntl

            fcntl.flock(holder, fcntl.LOCK_EX)
            with self.assertRaises(installer.InstallError) as caught:
                installer.render("panel.example.com", root=str(self.root))
        self.assertEqual(caught.exception.code, 7)

    def test_plan_lists_files_and_what_is_not_done(self):
        result = installer.plan("panel.example.com", root=str(self.root))
        self.assertIn("etc/donino/panel.env", result["files"])
        self.assertIn("start or enable systemd services", result["not_done_by_this_slice"])
        self.assertNotIn("SECRET", str(result))


if __name__ == "__main__":
    unittest.main()
