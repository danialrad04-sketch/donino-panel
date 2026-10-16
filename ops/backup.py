"""Authenticated, streaming encrypted control-plane backup bundles."""

import argparse
import fcntl
import json
import os
import secrets
import shutil
import stat
import tempfile
import time
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app import __version__
from app.storage import backup_database, import_sqlite, restore_archive, require_empty
from app.node_identity import PKI_FILES, pki_directory

from .common import InstallError, atomic_write, read_env, run

MAGIC = b"DONINO-BACKUP-1\0"
CHUNK = 1024 * 1024


def backup_key(path, *, create=False):
    path = Path(path)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b" if create else "rb") as file:
        fcntl.flock(file, fcntl.LOCK_EX if create else fcntl.LOCK_SH)
        mode = os.fstat(file.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise InstallError("Backup key must be a private regular file (0600)")
        key = file.read()
        if not key and create:
            key = secrets.token_bytes(32)
            file.write(key)
            file.flush()
            os.fsync(file.fileno())
        if len(key) != 32:
            raise InstallError("Invalid backup key length")
        return key


def encrypt_file(source, destination, key):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".donino-", dir=destination.parent)
    nonce = secrets.token_bytes(12)
    header = MAGIC + nonce
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    try:
        with os.fdopen(fd, "wb") as output, open(source, "rb") as input:
            output.write(header)
            while chunk := input.read(CHUNK):
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        # Hard linking atomically refuses overwrite of an existing destination.
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def decrypt_file(source, destination, key):
    """Caller uses a private temporary directory; no import before tag verification."""
    destination = Path(destination)
    created = False
    try:
        with open(source, "rb") as input:
            size = os.fstat(input.fileno()).st_size
            header = input.read(len(MAGIC) + 12)
            if not header.startswith(MAGIC) or size < len(header) + 16:
                raise InstallError("Invalid Donino backup header")
            input.seek(-16, 2)
            tag = input.read(16)
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(header[-12:], tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header)
            input.seek(len(header))
            remaining = size - len(header) - 16
            fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created = True
            with os.fdopen(fd, "wb") as output:
                while remaining:
                    chunk = input.read(min(CHUNK, remaining))
                    if not chunk:
                        raise InstallError("Truncated backup")
                    remaining -= len(chunk)
                    output.write(decryptor.update(chunk))
                output.write(decryptor.finalize())
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


@contextmanager
def panel_environment(path):
    values = read_env(path)
    old = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield values
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def create_bundle(
    destination,
    key_file,
    *,
    config=Path("/etc/donino/panel.env"),
    state=Path("/var/lib/donino-installer/state.json"),
):
    key = backup_key(key_file, create=True)
    with (
        tempfile.TemporaryDirectory(prefix="donino-backup-") as folder,
        panel_environment(config) as values,
    ):
        folder = Path(folder)
        database = folder / "database"
        kind = backup_database(database)
        manifest = {
            "format": "donino-control-bundle-v1",
            "app_version": __version__,
            "created_at_utc": int(time.time()),
            "database_format": kind,
            "domain": values.get("DONINO_PUBLIC_URL"),
            "entries": ["database", "config/panel.env"],
        }
        entries = {"database": database, "config/panel.env": Path(config)}
        master = Path(
            values.get(
                "DONINO_KEY_FILE", str(Path(values["DONINO_DB"]).parent / "master.key")
            )
        )
        if master.is_file():
            entries["data/master.key"] = master
        pki = pki_directory()
        if pki.exists():
            for name in (*PKI_FILES, "initialized"):
                path = pki / name
                if not path.is_file():
                    raise InstallError("Incomplete node PKI; backup refused")
                entries["data/pki/" + name] = path
        for name in ("panel.crt", "panel.key"):
            path = Path(config).parent / "tls" / name
            if path.is_file():
                entries["config/tls/" + name] = path
        if Path(state).is_file():
            entries["state/installer.json"] = Path(state)
        manifest["entries"] = sorted(entries)
        archive = folder / "bundle.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("manifest.json", json.dumps(manifest))
            for name, path in entries.items():
                output.write(path, name)
        encrypt_file(archive, destination, key)
    return manifest


def verified_bundle(source, key_file, folder):
    archive = Path(folder) / "bundle.zip"
    decrypt_file(source, archive, backup_key(key_file))
    allowed = {
        "database",
        "config/panel.env",
        "data/master.key",
        "config/tls/panel.crt",
        "config/tls/panel.key",
        "state/installer.json",
        *("data/pki/" + name for name in (*PKI_FILES, "initialized")),
    }
    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        entries = manifest.get("entries", [])
        if (
            manifest.get("format") != "donino-control-bundle-v1"
            or not set(entries) <= allowed
            or len(entries) != len(set(entries))
        ):
            raise InstallError("Invalid control-plane backup inventory")
        if not {"database", "config/panel.env"} <= set(entries) or sorted(
            bundle.namelist()
        ) != sorted(entries + ["manifest.json"]):
            raise InstallError("Incomplete or duplicate control-plane backup entries")
        for name in entries:
            target = Path(folder) / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as output, bundle.open(name) as input:
                shutil.copyfileobj(input, output, CHUNK)
    return manifest


def restore_bundle(
    source, key_file, *, config=Path("/etc/donino/panel.env"), apply=False
):
    with tempfile.TemporaryDirectory(prefix="donino-restore-") as folder:
        folder = Path(folder)
        manifest = verified_bundle(source, key_file, folder)
        if not apply:
            return manifest
        with panel_environment(config) as values:
            require_empty()
            master = Path(
                values.get(
                    "DONINO_KEY_FILE",
                    str(Path(values["DONINO_DB"]).parent / "master.key"),
                )
            )
            old = master.read_bytes() if master.exists() else None
            incoming = folder / "data/master.key"
            pki = pki_directory()
            pki_files = [
                name
                for name in (*PKI_FILES, "initialized")
                if (folder / "data/pki" / name).exists()
            ]
            if pki_files and len(pki_files) != len(PKI_FILES) + 1:
                raise InstallError("Incomplete PKI backup inventory")
            previous_pki = {
                name: (pki / name).read_bytes() if (pki / name).exists() else None
                for name in pki_files
            }
            try:
                for name in pki_files:
                    atomic_write(pki / name, (folder / "data/pki" / name).read_bytes())
                    if os.geteuid() == 0:
                        owner = Path(values["DONINO_DB"]).parent.stat()
                        os.chown(pki, owner.st_uid, owner.st_gid)
                        os.chown(pki / name, owner.st_uid, owner.st_gid)
                if incoming.exists():
                    atomic_write(master, incoming.read_bytes())
                    if os.geteuid() == 0:
                        owner = master.parent.stat()
                        os.chown(master, owner.st_uid, owner.st_gid)
                if manifest["database_format"] == "sqlite":
                    import_sqlite(folder / "database")
                elif manifest["database_format"] == "donino-zip":
                    restore_archive(folder / "database")
                else:
                    raise InstallError("Unknown backup database format")
            except BaseException:
                for name, content in previous_pki.items():
                    if content is None:
                        (pki / name).unlink(missing_ok=True)
                    else:
                        atomic_write(pki / name, content)
                        if os.geteuid() == 0:
                            owner = Path(values["DONINO_DB"]).parent.stat()
                            os.chown(pki / name, owner.st_uid, owner.st_gid)
                if old is None:
                    master.unlink(missing_ok=True)
                else:
                    atomic_write(master, old)
                    if os.geteuid() == 0:
                        owner = master.parent.stat()
                        os.chown(master, owner.st_uid, owner.st_gid)
                raise
        # Preserve destination DB credentials, domain and TLS; do not point a new
        # host at an old database or silently adopt an old domain/certificate.
        return manifest


def wait_ready(timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8000/readyz", timeout=2
            ) as response:
                if json.load(response).get("status") == "ok":
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.25)
    raise InstallError("Restored service did not become ready within 30 seconds", 6)


def main():
    parser = argparse.ArgumentParser(
        description="Encrypted Donino control-plane backup"
    )
    parser.add_argument("command", choices=["create", "inspect", "restore"])
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--key-file", type=Path, default=Path("/etc/donino/backup.key"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run control-plane backup/restore as root")
    if args.command == "create":
        destination = args.path or Path("/var/backups/donino") / (
            time.strftime("donino-%Y%m%dT%H%M%SZ-", time.gmtime())
            + secrets.token_hex(4)
            + ".dnb"
        )
        create_bundle(destination, args.key_file)
        print(
            "Encrypted backup saved. Preserve backup.key separately outside this host."
        )
    else:
        if not args.path:
            parser.error("Backup path is required")
        if args.command == "restore" and args.apply:
            # Reject invalid/tampered input before interrupting the service.
            restore_bundle(args.path, args.key_file, apply=False)
            with panel_environment(Path("/etc/donino/panel.env")):
                require_empty()
            run(["systemctl", "stop", "donino-panel"])
            try:
                result = restore_bundle(args.path, args.key_file, apply=True)
                run(["nginx", "-t"], capture=True)
                run(["systemctl", "reload", "nginx"])
            finally:
                run(["systemctl", "start", "donino-panel"])
                wait_ready()
        else:
            result = restore_bundle(args.path, args.key_file, apply=False)
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in ("format", "app_version", "created_at_utc", "domain")
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
