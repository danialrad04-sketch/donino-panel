import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from support import sqlite_only
from app.db import database, hash_password, initialize
from app.secrets import seal, unseal
from ops.backup import create_bundle, decrypt_file, encrypt_file, restore_bundle


class EncryptedFileTest(unittest.TestCase):
    def test_streaming_authentication_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            plain, encrypted, output = (
                root / name for name in ("plain", "encrypted", "output")
            )
            plain.write_bytes(os.urandom(2_500_000))
            key = secrets.token_bytes(32)
            encrypt_file(plain, encrypted, key)
            decrypt_file(encrypted, output, key)
            self.assertEqual(output.read_bytes(), plain.read_bytes())
            with self.assertRaises(FileExistsError):
                decrypt_file(encrypted, output, key)
            self.assertEqual(output.read_bytes(), plain.read_bytes())
            output.unlink()
            with self.assertRaises(InvalidTag):
                decrypt_file(encrypted, output, secrets.token_bytes(32))
            self.assertFalse(output.exists())
            data = bytearray(encrypted.read_bytes())
            data[len(data) // 2] ^= 1
            encrypted.write_bytes(data)
            with self.assertRaises(InvalidTag):
                decrypt_file(encrypted, output, key)
            self.assertFalse(output.exists())


@sqlite_only
class BundleRestoreTest(unittest.TestCase):
    def test_database_and_mfa_restore_and_nonempty_destination_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            key_file = root / "backup.key"
            seed = "JBSWY3DPEHPK3PXP"
            with patch.dict(
                os.environ,
                {
                    "DONINO_DB": str(source / "panel.db"),
                    "DONINO_DATABASE_URL": "",
                    "DONINO_KEY_FILE": str(source / "master.key"),
                },
            ):
                initialize()
                with database() as db:
                    db.execute(
                        "INSERT INTO admins VALUES(?,?,?)",
                        ("owner", hash_password("test-owner-password"), "owner"),
                    )
                    db.execute(
                        "INSERT INTO admin_mfa VALUES(?,?,1,0,'[]',1)",
                        ("owner", seal(seed)),
                    )
                    db.execute(
                        "INSERT INTO sessions(token,username,expires) VALUES('old-session','owner',9999999999)"
                    )
                    db.execute(
                        "INSERT INTO api_tokens(id,username,name,digest,scope,expires,created) VALUES('old-token','owner','old','hashed','full',9999999999,1)"
                    )
                source_env = source / "panel.env"
                source_env.write_text(
                    f"DONINO_DB={source / 'panel.db'}\nDONINO_DATABASE_URL=\nDONINO_KEY_FILE={source / 'master.key'}\n"
                )
                create_bundle(
                    root / "backup.dnb",
                    key_file,
                    config=source_env,
                    state=root / "absent",
                )
            with patch.dict(
                os.environ,
                {
                    "DONINO_DB": str(target / "panel.db"),
                    "DONINO_DATABASE_URL": "",
                    "DONINO_KEY_FILE": str(target / "master.key"),
                },
            ):
                initialize()
                target_env = target / "panel.env"
                target_env.write_text(
                    f"DONINO_DB={target / 'panel.db'}\nDONINO_DATABASE_URL=\nDONINO_KEY_FILE={target / 'master.key'}\n"
                )
                restore_bundle(
                    root / "backup.dnb", key_file, config=target_env, apply=True
                )
                with database() as db:
                    self.assertEqual(
                        unseal(
                            db.execute("SELECT secret FROM admin_mfa").fetchone()[0]
                        ),
                        seed,
                    )
                    self.assertEqual(
                        db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0
                    )
                    self.assertEqual(
                        db.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0], 0
                    )
                original = (target / "master.key").read_bytes()
                with self.assertRaisesRegex(ValueError, "empty destination"):
                    restore_bundle(
                        root / "backup.dnb", key_file, config=target_env, apply=True
                    )
                self.assertEqual((target / "master.key").read_bytes(), original)
