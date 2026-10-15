import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


def db_path():
    return Path(os.environ.get("DONINO_DB", "data/donino.db"))


@contextmanager
def database():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = sqlite3.connect(path, timeout=20)
    os.chmod(path, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=20000")
    try:
        # Serialize read-modify-write operations across requests/workers.
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


SCHEMA_VERSION = 3
MAX_DEVICES_PER_USER = 20


def migration_backup(tag="v2"):
    """Called before DDL, while another connection holds the writer reservation."""
    path = db_path()
    destination = path.with_name(
        path.name + ".pre-" + tag + "-" + uuid.uuid4().hex[:12] + ".db"
    )
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    source, target = sqlite3.connect(path), sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        source.close()
        target.close()


def initialize():
    with database() as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                "Database is newer than this Donino version; refusing to open it"
            )
        existing = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if existing and version < SCHEMA_VERSION:
            columns = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
            if not {"id", "credential", "used", "token"}.issubset(columns):
                raise RuntimeError(
                    "Unrecognized database schema; automatic migration refused"
                )
            # One backup per upgrade run, named after the oldest step being applied.
            migration_backup("v2" if version < 2 else "v3")
        # execute() keeps all DDL and the version update inside the same transaction.
        schema = """
        CREATE TABLE IF NOT EXISTS admins (
          username TEXT PRIMARY KEY, password TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('owner','operator','viewer')));
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
          expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (
          address TEXT PRIMARY KEY, attempts INTEGER NOT NULL, until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, credential TEXT NOT NULL, name TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          quota INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
          expires INTEGER, token TEXT UNIQUE NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS nodes (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
          token TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          last_seen INTEGER, applied_revision TEXT, error TEXT);
        CREATE TABLE IF NOT EXISTS inbounds (
          id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          name TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL,
          settings TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          UNIQUE(node_id,port));
        CREATE TABLE IF NOT EXISTS counters (
          node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          epoch TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          up INTEGER NOT NULL, down INTEGER NOT NULL,
          PRIMARY KEY(node_id,epoch,user_id));
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
          actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
        """
        for statement in schema.split(";"):
            if statement.strip():
                db.execute(statement)
        if version < 2:
            for column in ("uploaded", "downloaded", "legacy_used"):
                db.execute(
                    f"ALTER TABLE users ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"
                )
            db.execute("UPDATE users SET legacy_used=used")
            db.execute(
                "ALTER TABLE nodes ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''"
            )
            db.execute(
                "ALTER TABLE nodes ADD COLUMN apply_mode TEXT NOT NULL DEFAULT ''"
            )
            db.execute("ALTER TABLE nodes ADD COLUMN core_running INTEGER")
            db.execute(
                "ALTER TABLE nodes ADD COLUMN pending_usage INTEGER NOT NULL DEFAULT 0"
            )
            db.execute("PRAGMA user_version=2")
        if version < 3:
            migrate_to_v3(db)
            db.execute("PRAGMA user_version=3")


def migrate_to_v3(db):
    """Devices, scoped API tokens, TOTP state and session metadata.

    Identity is preserved: every existing user receives one default device whose
    id and secret equal the user's id and credential. Xray client emails (the
    counter keys) therefore stay identical, so the compiled node configuration
    and all stored counter baselines remain valid and no node restarts because
    of the upgrade itself.
    """
    db.execute(
        """CREATE TABLE devices (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL, secret TEXT NOT NULL,
          token TEXT UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1,
          is_default INTEGER NOT NULL DEFAULT 0,
          uploaded INTEGER NOT NULL DEFAULT 0,
          downloaded INTEGER NOT NULL DEFAULT 0,
          created INTEGER NOT NULL,
          UNIQUE(user_id,name))"""
    )
    db.execute("CREATE INDEX devices_user ON devices(user_id)")
    db.execute(
        "INSERT INTO devices(id,user_id,name,secret,token,enabled,is_default,created) "
        "SELECT id,id,'default',credential,NULL,1,1,created FROM users"
    )
    # Counter baselines are per Xray client (device), not per user. Existing rows
    # already use the default device id, which equals the user id.
    db.execute(
        """CREATE TABLE counters_v3 (
          node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          epoch TEXT NOT NULL,
          device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
          up INTEGER NOT NULL, down INTEGER NOT NULL,
          PRIMARY KEY(node_id,epoch,device_id))"""
    )
    db.execute(
        "INSERT INTO counters_v3 SELECT node_id,epoch,user_id,up,down FROM counters"
    )
    db.execute("DROP TABLE counters")
    db.execute("ALTER TABLE counters_v3 RENAME TO counters")
    for column, definition in (
        ("sid", "TEXT"),
        ("created", "INTEGER NOT NULL DEFAULT 0"),
        ("address", "TEXT NOT NULL DEFAULT ''"),
        ("agent", "TEXT NOT NULL DEFAULT ''"),
    ):
        db.execute(f"ALTER TABLE sessions ADD COLUMN {column} {definition}")
    for row in db.execute("SELECT token,expires FROM sessions").fetchall():
        db.execute(
            "UPDATE sessions SET sid=?,created=? WHERE token=?",
            (secrets.token_hex(8), row["expires"] - 43200, row["token"]),
        )
    db.execute("CREATE UNIQUE INDEX sessions_sid ON sessions(sid)")
    db.execute(
        """CREATE TABLE admin_mfa (
          username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,
          secret TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 0,
          last_step INTEGER NOT NULL DEFAULT 0,
          recovery TEXT NOT NULL DEFAULT '[]',
          created INTEGER NOT NULL)"""
    )
    db.execute(
        """CREATE TABLE api_tokens (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
          name TEXT NOT NULL,
          digest TEXT UNIQUE NOT NULL,
          scope TEXT NOT NULL CHECK(scope IN ('read','users','full')),
          expires INTEGER NOT NULL, created INTEGER NOT NULL,
          last_used INTEGER)"""
    )
    db.execute("CREATE INDEX api_tokens_user ON api_tokens(username)")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return salt + ":" + hashed.hex()


def verify_password(password, stored):
    salt, expected = stored.split(":")
    actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return hmac.compare_digest(actual.hex(), expected)


def audit(db, actor, action, target=""):
    db.execute(
        "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
        (int(time.time()), actor, action, target),
    )
