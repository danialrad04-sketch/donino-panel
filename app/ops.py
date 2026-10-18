"""Operational commands: read-only doctor, checksummed backup and verified restore.

SQLite: consistent copy through the online backup API.
PostgreSQL: pg_dump custom-format dump, verified with pg_restore --list before use.
Both write a JSON manifest with the SHA-256, schema version and app version.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

from . import __version__
from .db import (
    SCHEMA_VERSION,
    database,
    db_path,
    is_postgres,
    pg_dump,
    schema_version,
    table_exists,
    pg_client_connection,
)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_database(source, destination):
    """Consistent copy through SQLite's online backup API."""
    src = sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
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


def _tool(name):
    found = shutil.which(name)
    if not found:
        raise RuntimeError(
            f"{name} is not installed; install the postgresql-client package"
        )
    return found


def _write_manifest(destination, version):
    manifest = {
        "file": destination.name,
        "sha256": _sha256(destination),
        "schema_version": version,
        "app_version": __version__,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path = destination.with_name(destination.name + ".manifest.json")
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(manifest, handle, indent=2)
    return manifest


def _report_schema(add, version):
    if version > SCHEMA_VERSION:
        add(
            "FAIL",
            "schema",
            f"database {version} is newer than this release {SCHEMA_VERSION}",
        )
    elif version < SCHEMA_VERSION:
        add(
            "WARN",
            "schema",
            f"database {version}; run `migrate` (current {SCHEMA_VERSION})",
        )
    else:
        add("OK", "schema", str(version))


def _report_counts(add, users, devices, nodes, owners):
    add("OK", "counts", f"users={users} devices={devices} nodes={nodes}")
    if owners == 0:
        add("FAIL", "owners", "no owner account; create one with `admin`")
    else:
        add("OK", "owners", str(owners))


def _doctor_sqlite(add, path):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        add(
            "WARN",
            "database permissions",
            f"{oct(mode)} is readable by others; use 0600",
        )
    else:
        add("OK", "database permissions", oct(mode))
    _report_schema(add, _schema_version(path))
    result = _integrity(path)
    add("OK" if result == "ok" else "FAIL", "integrity_check", result)
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        devices = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        nodes = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        owners = db.execute(
            "SELECT COUNT(*) FROM admins WHERE role='owner'"
        ).fetchone()[0]
    _report_counts(add, users, devices, nodes, owners)


def _doctor_postgres(add):
    try:
        with database() as db:
            if not table_exists(db, "users"):
                add("WARN", "database", "PostgreSQL reachable but empty; run `migrate`")
                return
            version = schema_version(db)
            users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            devices = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            nodes = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            owners = db.execute(
                "SELECT COUNT(*) FROM admins WHERE role='owner'"
            ).fetchone()[0]
    except Exception as error:  # psycopg errors; never echo the connection string
        add("FAIL", "database", f"PostgreSQL unreachable: {type(error).__name__}")
        return
    add("OK", "database", "PostgreSQL reachable")
    _report_schema(add, version)
    _report_counts(add, users, devices, nodes, owners)
    if shutil.which("pg_dump") and shutil.which("pg_restore"):
        add("OK", "pg tools", "pg_dump and pg_restore found")
    else:
        add(
            "FAIL",
            "pg tools",
            "install postgresql-client; backups and restores need it",
        )


def doctor():
    """Read-only health report. Never prints secrets, tokens or keys."""
    rows = []

    def add(level, name, detail):
        rows.append((level, name, detail))

    if is_postgres():
        _doctor_postgres(add)
    else:
        path = db_path()
        if not path.exists():
            add("FAIL", "database", f"not found at {path}")
        else:
            _doctor_sqlite(add, path)

    public = os.environ.get("DONINO_PUBLIC_URL", "")
    if not public:
        add(
            "WARN",
            "DONINO_PUBLIC_URL",
            "not set; subscription links use the request host",
        )
    elif not public.startswith("https://"):
        add(
            "WARN",
            "DONINO_PUBLIC_URL",
            "not HTTPS; clients and browsers should use HTTPS",
        )
    else:
        add("OK", "DONINO_PUBLIC_URL", "https")
    if os.environ.get("DONINO_SECURE_COOKIE", "true").lower() == "false":
        add(
            "WARN",
            "DONINO_SECURE_COOKIE",
            "false; only acceptable for local HTTP testing",
        )
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
    destination.parent.mkdir(parents=True, exist_ok=True)
    if is_postgres():
        with database() as db:
            version = schema_version(db)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        pg_dump(destination)
        return _write_manifest(destination, version)
    source = db_path()
    if not source.exists():
        raise FileNotFoundError(f"database not found at {source}")
    _copy_database(source, destination)
    return _write_manifest(destination, _schema_version(destination))


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
    if is_postgres():
        return _restore_postgres(source, manifest, replace)

    version = _schema_version(source)
    if version != int(manifest["schema_version"]):
        raise ValueError("manifest schema does not match the backup")
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"backup schema {version} is newer than this release {SCHEMA_VERSION}"
        )
    if _integrity(source) != "ok":
        raise ValueError("integrity_check failed on the backup")
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as db:
        if db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("foreign_key_check failed on the backup")

    target = db_path()
    safety = None
    if target.exists():
        if not replace:
            raise FileExistsError(f"{target} exists; pass replace=True to overwrite it")
        safety = target.with_name(f"{target.name}.pre-restore-{time.time_ns()}.db")
        _copy_database(target, safety)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_name(target.name + ".restoring")
    if staging.exists():
        staging.unlink()
    _copy_database(source, staging)
    with sqlite3.connect(staging) as db:
        db.execute("DELETE FROM sessions")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='api_tokens'"
        ).fetchone():
            db.execute("DELETE FROM api_tokens")
        if version >= 12:
            from .tunnel_endpoints import invalidate_all

            invalidate_all(db)
        if version >= 13:
            from .smart_dns import invalidate_restored

            invalidate_restored(db)
    os.replace(staging, target)
    return {
        "restored_from": str(source),
        "schema_version": version,
        "safety_copy": str(safety) if safety else None,
    }


def _restore_postgres(source, manifest, replace):
    version = int(manifest["schema_version"])
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"backup schema {version} is newer than this release {SCHEMA_VERSION}"
        )
    listing = subprocess.run(
        [_tool("pg_restore"), "--list", str(source)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if listing.returncode != 0:
        raise ValueError("backup is not a readable PostgreSQL dump")

    safety = None
    with database() as db:
        populated = table_exists(db, "users")
    if populated:
        if not replace:
            raise FileExistsError(
                "the database already holds data; pass replace=True to overwrite it"
            )
        safety = db_path().parent / f"donino.pre-restore-{time.time_ns()}.dump"
        safety.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(safety, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        pg_dump(safety)
    connection, environment = pg_client_connection()
    result = subprocess.run(
        [
            _tool("pg_restore"),
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--exit-on-error",
            "--single-transaction",
            "--dbname",
            connection,
            str(source),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        hint = f"; previous database kept at {safety}" if safety else ""
        raise RuntimeError(f"pg_restore failed; transaction rolled back{hint}")
    with database() as db:
        if schema_version(db) != version:
            raise ValueError("restored schema differs from the backup manifest")
        db.execute("DELETE FROM sessions")
        if table_exists(db, "api_tokens"):
            db.execute("DELETE FROM api_tokens")
        if table_exists(db, "tunnel_checks"):
            from .tunnel_endpoints import invalidate_all

            invalidate_all(db)
        if table_exists(db, "smart_exits"):
            from .smart_dns import invalidate_restored

            invalidate_restored(db)
    return {
        "restored_from": str(source),
        "schema_version": version,
        "safety_copy": str(safety) if safety else None,
    }
