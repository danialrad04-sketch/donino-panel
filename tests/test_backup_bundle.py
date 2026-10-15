import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from app.db import database, digest, hash_password, initialize
from app.security import cipher
from ops.backup import create_bundle, decrypt_file, encrypt_file, restore_bundle
from ops.common import atomic_write


class EncryptedBackupTest(unittest.TestCase):
    def test_streaming_authentication_tamper_and_existing_target_preservation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.write_bytes(secrets.token_bytes(2_200_000))
            key = secrets.token_bytes(32)
            encrypted = root / "backup.dnb"
            encrypt_file(source, encrypted, key)
            restored = root / "restored"
            decrypt_file(encrypted, restored, key)
            self.assertEqual(restored.read_bytes(), source.read_bytes())
            with self.assertRaises(FileExistsError):
                decrypt_file(encrypted, restored, key)
            self.assertEqual(restored.read_bytes(), source.read_bytes())
            with self.assertRaises(InvalidTag):
                decrypt_file(encrypted, root / "wrong-key", secrets.token_bytes(32))
            self.assertFalse((root / "wrong-key").exists())
            tampered = bytearray(encrypted.read_bytes())
            tampered[40] ^= 1
            (root / "tampered").write_bytes(tampered)
            with self.assertRaises(InvalidTag):
                decrypt_file(root / "tampered", root / "unverified", key)
            self.assertFalse((root / "unverified").exists())
            self.assertEqual(encrypted.stat().st_mode & 0o777, 0o600)

    def test_bundle_restores_database_and_matching_mfa_key_but_not_old_admin_sessions(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            target.mkdir()
            values = {
                "DONINO_DATABASE_URL": "",
                "DONINO_DB": str(source / "data.db"),
                "DONINO_KEY_FILE": str(source / "master.key"),
                "DONINO_PUBLIC_URL": "https://source.test",
            }
            config = source / "panel.env"
            atomic_write(config, "".join(k + "=" + v + "\n" for k, v in values.items()))
            with patch.dict(os.environ, values):
                initialize()
                encrypted_seed = cipher().encrypt(b"test-seed").decode()
                with database() as db:
                    db.execute(
                        "INSERT INTO admins VALUES(?,?,?)",
                        ("owner", hash_password("long-test-password"), "owner"),
                    )
                    db.execute(
                        "INSERT INTO admin_mfa(username,secret,enabled) VALUES(?,?,1)",
                        ("owner", encrypted_seed),
                    )
                    db.execute(
                        "INSERT INTO sessions VALUES(?,?,?)",
                        (digest("old-session"), "owner", 9999999999),
                    )
            original_key = (source / "master.key").read_bytes()
            key_file = root / "backup.key"
            bundle = root / "control.dnb"
            create_bundle(bundle, key_file, config=config, state=root / "absent-state")
            target_values = {
                **values,
                "DONINO_DB": str(target / "data.db"),
                "DONINO_KEY_FILE": str(target / "master.key"),
                "DONINO_PUBLIC_URL": "https://destination.test",
            }
            target_config = target / "panel.env"
            atomic_write(
                target_config,
                "".join(k + "=" + v + "\n" for k, v in target_values.items()),
            )
            report = restore_bundle(bundle, key_file, config=target_config, apply=False)
            self.assertEqual(report["domain"], "https://source.test")
            self.assertFalse((target / "data.db").exists())
            restore_bundle(bundle, key_file, config=target_config, apply=True)
            self.assertEqual((target / "master.key").read_bytes(), original_key)
            self.assertIn("https://destination.test", target_config.read_text())
            with patch.dict(os.environ, target_values), database() as db:
                row = db.execute("SELECT secret FROM admin_mfa").fetchone()
                self.assertEqual(cipher().decrypt(row["secret"].encode()), b"test-seed")
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0
                )
            previous = (target / "master.key").read_bytes()
            with self.assertRaisesRegex(RuntimeError, "contains data"):
                restore_bundle(bundle, key_file, config=target_config, apply=True)
            self.assertEqual((target / "master.key").read_bytes(), previous)
