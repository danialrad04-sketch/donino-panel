"""Private consistent backups and non-destructive database migration."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from sqlalchemy import select

from .db import _engine, database, database_url, db_path, initialize
from .models import metadata


def reserve(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    return path


def backup_database(destination):
    destination = reserve(destination)
    try:
        if not os.environ.get("DONINO_DATABASE_URL"):
            source, target = sqlite3.connect(db_path()), sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                source.close()
                target.close()
            return "sqlite"
        engine = _engine(database_url())
        with engine.connect().execution_options(
            isolation_level="REPEATABLE READ"
        ) as connection:
            with connection.begin():
                revision = connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).scalar_one()
                with zipfile.ZipFile(
                    destination, "w", compression=zipfile.ZIP_DEFLATED
                ) as archive:
                    archive.writestr(
                        "manifest.json",
                        json.dumps(
                            {
                                "format": "donino-database-v1",
                                "revision": revision,
                                "tables": [t.name for t in metadata.sorted_tables],
                            }
                        ),
                    )
                    for table in metadata.sorted_tables:
                        with archive.open(
                            table.name + ".jsonl", "w", force_zip64=True
                        ) as stream:
                            rows = (
                                connection.execution_options(stream_results=True)
                                .execute(select(table))
                                .mappings()
                            )
                            for row in rows:
                                stream.write(
                                    (
                                        json.dumps(dict(row), ensure_ascii=False) + "\n"
                                    ).encode()
                                )
        return "donino-zip"
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _check_empty(db):
    for table in metadata.sorted_tables:
        if db.execute(f'SELECT 1 FROM "{table.name}" LIMIT 1').fetchone():
            raise RuntimeError("Destination contains data; import refused")


def _reset_sequences(db):
    if db.postgres:
        db.execute(
            "SELECT setval(pg_get_serial_sequence('audit','id'), COALESCE((SELECT MAX(id) FROM audit),0)+1, false)"
        )


def import_sqlite(source_path):
    """Clone source into a private snapshot, upgrade the clone, then atomically copy.

    The original source is not modified. Destination must be a fresh database.
    No SQL, templates or code from the source is executed.
    """
    source_path = Path(source_path).resolve()
    if not source_path.is_file():
        raise RuntimeError("Source database does not exist")
    if not os.environ.get("DONINO_DATABASE_URL") and source_path == db_path().resolve():
        raise RuntimeError("Source and destination must differ")
    with tempfile.TemporaryDirectory(prefix="donino-import-") as folder:
        snapshot = reserve(Path(folder) / "snapshot.db")
        source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)
        target = sqlite3.connect(snapshot)
        try:
            source.backup(target)
        finally:
            source.close()
            target.close()
        env = dict(os.environ, DONINO_DB=str(snapshot))
        env.pop("DONINO_DATABASE_URL", None)
        subprocess.run(
            [sys.executable, "-m", "app.cli", "migrate"],
            env=env,
            check=True,
            capture_output=True,
        )
        initialize()
        with sqlite3.connect(snapshot) as source, database() as db:
            source.row_factory = sqlite3.Row
            db.lock("database-import")
            _check_empty(db)
            for table in metadata.sorted_tables:
                cursor = source.execute(f'SELECT * FROM "{table.name}"')
                while batch := cursor.fetchmany(500):
                    db.connection.execute(table.insert(), [dict(row) for row in batch])
            _reset_sequences(db)


def restore_archive(source_path):
    """Restore a Donino PG archive into an initialized empty database."""
    initialize()
    with zipfile.ZipFile(source_path) as archive, database() as db:
        db.lock("database-import")
        _check_empty(db)
        manifest = json.loads(archive.read("manifest.json"))
        revision = db.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        if (
            manifest.get("format") != "donino-database-v1"
            or manifest.get("revision") != revision
        ):
            raise RuntimeError("Backup schema does not match this Donino version")
        expected = [table.name for table in metadata.sorted_tables]
        if manifest.get("tables") != expected:
            raise RuntimeError("Backup table inventory mismatch")
        if sorted(archive.namelist()) != sorted(
            ["manifest.json"] + [name + ".jsonl" for name in expected]
        ):
            raise RuntimeError("Unexpected or duplicate backup entries")
        for table in metadata.sorted_tables:
            with archive.open(table.name + ".jsonl") as stream:
                batch = []
                for line in stream:
                    row = json.loads(line)
                    if set(row) != set(table.c.keys()):
                        raise RuntimeError("Backup column inventory mismatch")
                    batch.append(row)
                    if len(batch) >= 500:
                        db.connection.execute(table.insert(), batch)
                        batch = []
                if batch:
                    db.connection.execute(table.insert(), batch)
        _reset_sequences(db)
