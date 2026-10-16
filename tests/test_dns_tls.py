import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent.dns_tls import install


class DNSTLSTest(unittest.TestCase):
    def test_atomic_certificate_pair_rotation_and_private_permissions(self):
        def pair():
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dns.test")])
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .sign(key, hashes.SHA256())
            )
            return {
                "panel.crt": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "panel.key": key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
            }

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "dns-tls"
            first, second = pair(), pair()
            install(root, first)
            old = (root / "current").readlink()
            install(root, first)
            self.assertEqual((root / "current").readlink(), old)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "current/panel.key").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ssl.SSLError):
                install(
                    root,
                    {"panel.crt": second["panel.crt"], "panel.key": first["panel.key"]},
                )
            self.assertEqual((root / "current").readlink(), old)
            install(root, second)
            self.assertNotEqual((root / "current").readlink(), old)
            link = Path(folder) / "symbolic"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                install(link, first)
