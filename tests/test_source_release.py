import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from ops.bootstrap import unpack_verified
from ops.common import InstallError
from ops.manifest import verify_manifest, write_manifest


class SourceReleaseTest(unittest.TestCase):
    def package(self, *, extra=None, corrupt=False):
        files = {
            "ops/install.py": b"print('verified')\n",
            "app/main.py": b"# fixture\n",
            "LICENSE": b"fixture\n",
            "requirements.lock": b"fixture==1\n",
        }
        inventory = {
            name: hashlib.sha256(content).hexdigest() for name, content in files.items()
        }
        digest = hashlib.sha256()
        for name, checksum in sorted(inventory.items()):
            digest.update(name.encode() + b"\0" + bytes.fromhex(checksum))
        manifest = {
            "format": "donino-source-v1",
            "version": "test",
            "source_sha256": digest.hexdigest(),
            "files": inventory,
        }
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, content in files.items():
                data = content + (
                    b"tampered" if corrupt and name == "app/main.py" else b""
                )
                info = tarfile.TarInfo("source/" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if extra:
                info = tarfile.TarInfo(extra)
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
        return output.getvalue(), manifest

    def test_release_extracts_only_inventory_and_refuses_tampering_or_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            destination = root / "valid"
            destination.mkdir()
            data, manifest = self.package(extra="source/sitecustomize.py")
            unpack_verified(data, manifest, destination)
            self.assertFalse((destination / "sitecustomize.py").exists())
            self.assertEqual(
                (destination / "ops/install.py").read_bytes(), b"print('verified')\n"
            )
            data, manifest = self.package(corrupt=True)
            bad = root / "corrupt"
            bad.mkdir()
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                unpack_verified(data, manifest, bad)
            data, manifest = self.package(extra="source/../../escaped")
            unsafe = root / "unsafe"
            unsafe.mkdir()
            with self.assertRaisesRegex(RuntimeError, "Unsafe archive"):
                unpack_verified(data, manifest, unsafe)
            self.assertFalse((root / "escaped").exists())

    def test_manifest_is_reproducible_and_rejects_changed_or_missing_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            files = {
                "app/main.py": "# fixture",
                "app/__init__.py": '__version__="1.0.0a2"',
                "migrations/env.py": "# fixture",
                "ops/install.py": "# fixture",
                "requirements.txt": "# fixture",
                "requirements.lock": "# fixture",
                "LICENSE": "fixture",
            }
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            original = write_manifest(root)
            self.assertEqual(write_manifest(root), original)
            self.assertEqual(verify_manifest(root), original)
            (root / "app/main.py").write_text("# changed")
            with self.assertRaises(InstallError):
                verify_manifest(root)
            (root / "app/main.py").unlink()
            with self.assertRaises(InstallError):
                verify_manifest(root)
