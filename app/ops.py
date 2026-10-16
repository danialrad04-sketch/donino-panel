"""Operational commands: read-only doctor, checksummed backup and verified restore."""

import hashlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path

from . import __version__
from .db import SCHEMA_VERSION, db_path


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_database(source, destination):
    """Consistent copy through SQLite's online backup API."""
    src = sqlite3.connect(source)
    dst = sqlite3.connect(destination)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def _schema_version(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def _integrity(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        return db.execute("PRAGMA integrity_check").fetchone()[0]


def doctor():
    """Read-only health report. Never prints secrets, tokens or keys."""
    rows = []

    def add(level, name, detail):
        rows.append((level, name, detail))

    path = db_path()
    if not path.exists():
        add("FAIL", "database", f"not found at {path}")
    else:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            add("WARN", "database permissions", f"{oct(mode)} is readable by others; use 0600")
        else:
            add("OK", "database permissions", oct(mode))
        version = _schema_version(path)
        if version > SCHEMA_VERSION:
            add("FAIL", "schema", f"database {version} is newer than this release {SCHEMA_VERSION}")
        elif version < SCHEMA_VERSION:
            add("WARN", "schema", f"database {version}; run `migrate` (current {SCHEMA_VERSION})")
        else:
            add("OK", "schema", str(version))
        result = _integrity(path)
        add("OK" if result == "ok" else "FAIL", "integrity_check", result)
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            devices = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            nodes = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            owners = db.execute("SELECT COUNT(*) FROM admins WHERE role='owner'").fetchone()[0]
        add("OK", "counts", f"users={users} devices={devices} nodes={nodes}")
        if owners == 0:
            add("FAIL", "owners", "no owner account; create one with `admin`")
        else:
            add("OK", "owners", str(owners))

    public = os.environ.get("DONINO_PUBLIC_URL", "")
    if not public:
        add("WARN", "DONINO_PUBLIC_URL", "not set; subscription links use the request host")
    elif not public.startswith("https://"):
        add("WARN", "DONINO_PUBLIC_URL", "not HTTPS; clients and browsers should use HTTPS")
    else:
        add("OK", "DONINO_PUBLIC_URL", "https")
    if os.environ.get("DONINO_SECURE_COOKIE", "true").lower() == "false":
        add("WARN", "DONINO_SECURE_COOKIE", "false; only acceptable for local HTTP testing")
    else:
        add("OK", "DONINO_SECURE_COOKIE", "secure")

    add("OK", "version", __version__)
    failed = any(level == "FAIL" for level, _, _ in rows)
    return rows, 1 if failed else 0


def backup(destination):
    """Write a consistent copy and a manifest with its SHA-256 and schema version."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(f"{destination} already exists; choose a new name")
    source = db_path()
    if not source.exists():
        raise FileNotFoundError(f"database not found at {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    _copy_database(source, destination)
    manifest = {
        "file": destination.name,
        "sha256": _sha256(destination),
        "schema_version": _schema_version(destination),
        "app_version": __version__,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path = destination.with_name(destination.name + ".manifest.json")
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(manifest, handle, indent=2)
    return manifest


def restore(source, replace=False):
    """Restore a backup only after its checksum, schema and integrity are verified.

    An existing database is first copied to a timestamped safety file. Run this
    with the panel service stopped so no request writes during the swap.
    """
    source = Path(source)
    manifest_path = source.with_name(source.name + ".manifest.json")
    if not source.exists():
        raise FileNotFoundError(f"backup not found: {source}")
    if not manifest_path.exists():
        raise ValueError("manifest missing; refusing to restore an unverified file")
    manifest = json.loads(manifest_path.read_text())
    if _sha256(source) != manifest["sha256"]:
        raise ValueError("checksum mismatch; the backup is damaged or was changed")
    version = _schema_version(source)
    if version > SCHEMA_VERSION:
        raise ValueError(f"backup schema {version} is newer than this release {SCHEMA_VERSION}")
    if _integrity(source) != "ok":
        raise ValueError("integrity_check failed on the backup")

    target = db_path()
    safety = None
    if target.exists():
        if not replace:
            raise FileExistsError(f"{target} exists; pass replace=True to overwrite it")
        safety = target.with_name(
            f"{target.name}.pre-restore-{time.strftime('%Y%m%d%H%M%S')}.db"
        )
        _copy_database(target, safety)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_name(target.name + ".restoring")
    if staging.exists():
        staging.unlink()
    fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    _copy_database(source, staging)
    os.replace(staging, target)
    return {"restored_from": str(source), "schema_version": version, "safety_copy": str(safety) if safety else None}
