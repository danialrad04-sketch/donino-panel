import os
import secrets
import socket
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.db import database, digest
from app.main import app
from ops.common import InstallError, atomic_write
from ops.install import nginx_config
from ops.preflight import domain_name, resolve_and_check
from ops.tls import install_certificate, validate_certificate


class InstallerTest(unittest.TestCase):
    def test_dns_check_rejects_unmatched_ipv6_and_domain_injection(self):
        for value in (
            "https://example.com",
            "example.com;rm",
            "*.example.com",
            "example.com:443",
            "1.2.3.4",
            "x..com",
        ):
            with self.assertRaises(InstallError):
                domain_name(value)
        rows = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 80, 0, 0)),
        ]
        with (
            patch("ops.preflight.socket.getaddrinfo", return_value=rows),
            patch("ops.preflight.local_addresses", return_value={"127.0.0.1"}),
        ):
            with self.assertRaises(InstallError):
                resolve_and_check("example.com", ["203.0.113.1"])
            self.assertEqual(
                resolve_and_check("example.com", ["203.0.113.1", "2001:db8::1"]),
                ["2001:db8::1", "203.0.113.1"],
            )
        config = nginx_config("panel.example.com", tls=True)
        self.assertIn("access_log off", config)
        self.assertIn("/.well-known/acme-challenge/", config)
        self.assertIn("TLSv1.2 TLSv1.3", config)
        with self.assertRaises(InstallError):
            nginx_config("example.com;}", tls=True)

    def test_atomic_write_failure_preserves_original_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "state.json"
            atomic_write(target, "old")
            with patch("ops.common.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    atomic_write(target, "new")
            self.assertEqual(target.read_text(), "old")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(folder).iterdir()), [target])

    def test_real_certificate_identity_pair_and_reload_failure_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            now = datetime.now(timezone.utc)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "Donino test CA")]
            )
            ca = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=7))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )
                .sign(ca_key, hashes.SHA256())
            )
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panel.test")])
                )
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("panel.test")]),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )
            cert, private, authority = (
                root / "cert.pem",
                root / "key.pem",
                root / "ca.pem",
            )
            cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            private.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            authority.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
            validate_certificate("panel.test", cert, private, ca_file=authority)
            with self.assertRaises(InstallError):
                validate_certificate("wrong.test", cert, private, ca_file=authority)
            wrong = root / "wrong.key"
            wrong.write_bytes(
                ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            with self.assertRaises(InstallError):
                validate_certificate("panel.test", cert, wrong, ca_file=authority)
            destination = root / "live"
            install_certificate(
                "panel.test", cert, private, destination, ca_file=authority
            )
            before = [
                (destination / name).read_bytes() for name in ("panel.crt", "panel.key")
            ]
            with self.assertRaisesRegex(OSError, "reload failed"):
                install_certificate(
                    "panel.test",
                    cert,
                    private,
                    destination,
                    ca_file=authority,
                    reload=lambda: (_ for _ in ()).throw(OSError("reload failed")),
                )
            self.assertEqual(
                [
                    (destination / name).read_bytes()
                    for name in ("panel.crt", "panel.key")
                ],
                before,
            )
            self.assertEqual((destination / "panel.key").stat().st_mode & 0o777, 0o600)


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.token = secrets.token_urlsafe(40)
        self.env = patch.dict(
            os.environ,
            {
                "DONINO_DB": self.tmp.name + "/db.sqlite",
                "DONINO_DATABASE_URL": "",
                "DONINO_SECURE_COOKIE": "false",
                "DONINO_BOOTSTRAP_TOKEN_HASH": digest(self.token),
                "DONINO_BOOTSTRAP_EXPIRES": str(
                    int(datetime.now(timezone.utc).timestamp()) + 3600
                ),
            },
        )
        self.env.start()
        self.client = TestClient(app).__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.tmp.cleanup()

    def submit(self, token=None):
        return self.client.post(
            "/api/bootstrap",
            headers={"X-Donino": "1"},
            json={
                "token": token or self.token,
                "username": "owner",
                "password": "long-test-password",
            },
        )

    def test_first_owner_setup_is_atomic_one_use_and_requires_csrf_header(self):
        self.assertEqual(
            self.client.post(
                "/api/bootstrap",
                json={
                    "token": self.token,
                    "username": "owner",
                    "password": "long-test-password",
                },
            ).status_code,
            403,
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(lambda _: self.submit().status_code, range(4)))
        self.assertEqual(sorted(statuses), [201, 409, 409, 409])
        with database() as db:
            row = db.execute("SELECT * FROM admins").fetchone()
            self.assertEqual(row["role"], "owner")
            self.assertNotEqual(row["password"], "long-test-password")
        self.assertEqual(
            self.client.post(
                "/api/login",
                headers={"X-Donino": "1"},
                json={"username": "owner", "password": "long-test-password"},
            ).status_code,
            200,
        )

    def test_setup_expiry_and_failed_attempts_are_enforced(self):
        with patch.dict(os.environ, {"DONINO_BOOTSTRAP_EXPIRES": "1"}):
            self.assertEqual(self.submit().status_code, 404)
        for _ in range(10):
            self.assertEqual(self.submit("wrong-token-" * 4).status_code, 401)
        self.assertEqual(self.submit().status_code, 429)
        with database() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM admins").fetchone()[0], 0)

    def test_readiness_detects_database_failure_without_leaking_details(self):
        self.assertEqual(self.client.get("/readyz").json()["status"], "ok")
        with patch(
            "app.main.database", side_effect=OSError("private database location")
        ):
            response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("private", response.text)
            self.assertEqual(self.client.get("/healthz").status_code, 200)
