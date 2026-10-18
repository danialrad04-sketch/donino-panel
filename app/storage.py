"""Verified database archives used inside encrypted installation backups.

Uses the current main-branch schema and native SQLite/pg_dump tooling. It does
not adopt the incompatible Alembic schema from the earlier development branch.
"""

import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from . import ops
from .db import SCHEMA_VERSION, database, is_postgres, table_exists


def backup_database(destination):
    with tempfile.TemporaryDirectory(prefix="donino-database-") as folder:
        snapshot = Path(folder) / "snapshot"
        manifest = ops.backup(snapshot)
        manifest["backend"] = "postgresql" if is_postgres() else "sqlite"
        manifest["format"] = "donino-database-v2"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with (
            os.fdopen(fd, "wb") as file,
            zipfile.ZipFile(file, "w", zipfile.ZIP_DEFLATED) as bundle,
        ):
            bundle.writestr("manifest.json", json.dumps(manifest))
            bundle.write(snapshot, "snapshot")
    return "donino-zip"


def require_empty():
    with database() as db:
        for table in (
            "admins",
            "users",
            "nodes",
            "inbounds",
            "audit",
            "tunnel_bindings",
            "tunnel_checks",
            "tunnel_endpoints",
        ):
            if (
                table_exists(db, table)
                and db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            ):
                raise ValueError(
                    "Restore requires an empty destination; existing data was preserved"
                )


def restore_archive(source):
    require_empty()
    with tempfile.TemporaryDirectory(prefix="donino-database-restore-") as folder:
        snapshot = Path(folder) / "snapshot"
        with zipfile.ZipFile(source) as bundle:
            if sorted(bundle.namelist()) != ["manifest.json", "snapshot"]:
                raise ValueError("Invalid database archive inventory")
            manifest = json.loads(bundle.read("manifest.json"))
            expected = "postgresql" if is_postgres() else "sqlite"
            if (
                manifest.get("format") != "donino-database-v2"
                or manifest.get("backend") != expected
            ):
                raise ValueError(
                    "Backup backend differs from the destination; use an explicit data migration"
                )
            if int(manifest["schema_version"]) != SCHEMA_VERSION:
                raise ValueError("Restore requires the matching schema version")
            fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output, bundle.open("snapshot") as input:
                shutil.copyfileobj(input, output, 1024 * 1024)
        snapshot.with_name("snapshot.manifest.json").write_text(json.dumps(manifest))
        return ops.restore(snapshot, replace=True)


def import_sqlite(source):
    """Compatibility with native bundles; never silently change database backends."""
    require_empty()
    if is_postgres():
        raise ValueError(
            "SQLite-to-PostgreSQL migration is not implemented for this schema"
        )
    raise ValueError(
        "Legacy bundle format requires its matching release for restoration"
    )
