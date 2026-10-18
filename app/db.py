import hashlib
import hmac
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

try:  # PostgreSQL is optional; SQLite stays the default backend.
    import psycopg
except ImportError:  # pragma: no cover - exercised only without the postgres extra
    psycopg = None

SCHEMA_VERSION = 10
MAX_DEVICES_PER_USER = 20
# Arbitrary constant key for the PostgreSQL writer lock (serializes writers, like BEGIN IMMEDIATE).
_PG_WRITER_LOCK = 4541776

IntegrityErrors = (sqlite3.IntegrityError,) + (
    (psycopg.IntegrityError,) if psycopg else ()
)


def database_url():
    return os.environ.get("DONINO_DATABASE_URL", "").strip()


def is_postgres():
    return database_url().startswith(("postgresql://", "postgres://"))


def db_path():
    """SQLite file path. Also decides where file-based backups are written."""
    return Path(os.environ.get("DONINO_DB", "data/donino.db"))


class Row:
    """Row that supports both row[0] and row['name'], like sqlite3.Row."""

    __slots__ = ("_values", "_names")

    def __init__(self, values, names):
        self._values = tuple(values)
        self._names = names

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._values[self._names.index(key)]
        return self._values[key]

    def keys(self):
        return list(self._names)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


class PgResult:
    def __init__(self, cursor):
        self._cursor = cursor
        self._names = (
            [column.name for column in cursor.description] if cursor.description else []
        )

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        row = self._cursor.fetchone()
        return None if row is None else Row(row, self._names)

    def fetchall(self):
        return [Row(row, self._names) for row in self._cursor.fetchall()]

    def __iter__(self):
        for row in self._cursor:
            yield Row(row, self._names)


def _pg_sql(sql, params):
    """Translate the SQLite dialect used by the schema and queries into PostgreSQL."""
    if params:
        # Literal percent signs must be escaped once placeholders become %s.
        sql = sql.replace("%", "%%").replace("?", "%s")
    sql = re.sub(r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", sql)
    # Byte counters exceed 2 GB quickly, so every integer column is 64-bit.
    return re.sub(r"\bINTEGER\b", "BIGINT", sql)


class PgConnection:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql, params=()):
        # SQLite accepts bool as 0/1; psycopg would send a boolean into BIGINT columns.
        params = tuple(int(p) if isinstance(p, bool) else p for p in params)
        cursor = self.raw.cursor()
        cursor.execute(_pg_sql(sql, params), params or None)
        return PgResult(cursor)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


@contextmanager
def database():
    url = database_url()
    if url and not is_postgres():
        raise RuntimeError(
            "Unsupported DONINO_DATABASE_URL; use postgresql:// or leave it empty for SQLite"
        )
    if is_postgres():
        if psycopg is None:
            raise RuntimeError("PostgreSQL requires requirements-postgres.txt")
        connection = PgConnection(psycopg.connect(database_url(), connect_timeout=10))
    else:
        path = db_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = sqlite3.connect(path, timeout=20)
        os.chmod(path, 0o600)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute("PRAGMA busy_timeout=20000")
        connection = raw
    try:
        # Serialize read-modify-write operations across requests/workers.
        if is_postgres():
            connection.execute(f"SELECT pg_advisory_xact_lock({_PG_WRITER_LOCK})")
        else:
            connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def schema_version(db):
    if is_postgres():
        if not table_exists(db, "donino_meta"):
            return 0
        row = db.execute(
            "SELECT value FROM donino_meta WHERE key='schema_version'"
        ).fetchone()
        return row[0] if row else 0
    return db.execute("PRAGMA user_version").fetchone()[0]


def set_schema_version(db, version):
    if is_postgres():
        upsert(
            db, "donino_meta", ["key", "value"], ["schema_version", version], ["key"]
        )
    else:
        db.execute(f"PRAGMA user_version={int(version)}")


def table_exists(db, name):
    if is_postgres():
        row = db.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema=current_schema() AND table_name=?",
            (name,),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
    return row is not None


def table_columns(db, name):
    if is_postgres():
        rows = db.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND table_name=?",
            (name,),
        ).fetchall()
        return {row[0] for row in rows}
    return {row["name"] for row in db.execute(f"PRAGMA table_info({name})")}


def upsert(db, table, columns, values, keys):
    """Insert or replace a row keyed by `keys` on both backends."""
    names = ",".join(columns)
    marks = ",".join("?" * len(columns))
    if is_postgres():
        updates = ",".join(f"{c}=EXCLUDED.{c}" for c in columns if c not in keys)
        action = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
        sql = f"INSERT INTO {table}({names}) VALUES({marks}) ON CONFLICT({','.join(keys)}) {action}"
    else:
        sql = f"INSERT OR REPLACE INTO {table}({names}) VALUES({marks})"
    db.execute(sql, values)


def pg_dump(destination):
    """Write a custom-format PostgreSQL dump. Requires the pg_dump client tool."""
    tool = shutil.which("pg_dump")
    if not tool:
        raise RuntimeError(
            "pg_dump is not installed; install the postgresql-client package"
        )
    connection, environment = pg_client_connection()
    result = subprocess.run(
        [
            tool,
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(destination),
            "--dbname",
            connection,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "pg_dump failed; inspect database connectivity and client/server versions"
        )
    os.chmod(destination, 0o600)


def pg_client_connection():
    """Keep the database password out of command arguments and exception text."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    options = conninfo_to_dict(database_url())
    environment = dict(os.environ)
    password = options.pop("password", None)
    if password is not None:
        environment["PGPASSWORD"] = password
    return make_conninfo(**options), environment


def migration_backup(tag="v2"):
    """Called before DDL, while the writer lock is already held by this transaction."""
    path = db_path()
    if is_postgres():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pg_dump(path.parent / f"donino.pre-{tag}-{uuid.uuid4().hex[:12]}.dump")
        return
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
        if table_exists(db, "alembic_version"):
            raise RuntimeError(
                "This database belongs to the earlier development/1.0 schema; an explicit migration is required"
            )
        if is_postgres():
            db.execute(
                "CREATE TABLE IF NOT EXISTS donino_meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
            )
        version = schema_version(db)
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                "Database is newer than this Donino version; refusing to open it"
            )
        existing = table_exists(db, "users")
        if existing and version < SCHEMA_VERSION:
            columns = table_columns(db, "users")
            if not {"id", "credential", "used", "token"}.issubset(columns):
                raise RuntimeError(
                    "Unrecognized database schema; automatic migration refused"
                )
            # One backup per upgrade run, named after the oldest step being applied.
            migration_backup("v2" if version < 2 else f"v{SCHEMA_VERSION}")
        # Every statement runs inside this transaction, so DDL and the version update commit together.
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
            set_schema_version(db, 2)
        if version < 3:
            migrate_to_v3(db)
            set_schema_version(db, 3)
        if version < 4:
            migrate_to_v4(db)
            set_schema_version(db, 4)
        if version < 5:
            encrypt_legacy_mfa(db)
            set_schema_version(db, 5)
        if version < 6:
            db.execute("""CREATE TABLE usage_periods (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                period_no INTEGER NOT NULL, started INTEGER, ended INTEGER,
                uploaded INTEGER NOT NULL DEFAULT 0, downloaded INTEGER NOT NULL DEFAULT 0,
                legacy_used INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(user_id,period_no))""")
            db.execute("""INSERT INTO usage_periods(user_id,period_no,started,uploaded,downloaded,legacy_used)
                SELECT id,period_no,CASE WHEN period='monthly' THEN period_start ELSE created END,uploaded,downloaded,legacy_used FROM users""")
            db.execute("ALTER TABLE counters ADD COLUMN period_no INTEGER")
            db.execute(
                "ALTER TABLE users ADD COLUMN node_mode TEXT NOT NULL DEFAULT 'all' CHECK(node_mode IN ('all','selected'))"
            )
            db.execute("""CREATE TABLE user_nodes (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                PRIMARY KEY(user_id,node_id))""")
            db.execute("ALTER TABLE nodes ADD COLUMN desired_job TEXT")
            db.execute("""CREATE TABLE deployments (
                id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                revision TEXT NOT NULL, engine TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','applied','failed','superseded')),
                payload TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
                error TEXT NOT NULL DEFAULT '')""")
            db.execute("CREATE INDEX deployments_node ON deployments(node_id,created)")
            set_schema_version(db, 6)
        if version < 7:
            db.execute(
                "ALTER TABLE nodes ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'legacy' CHECK(auth_mode IN ('legacy','mtls'))"
            )
            db.execute(
                "ALTER TABLE nodes ADD COLUMN config_sequence INTEGER NOT NULL DEFAULT 0"
            )
            db.execute("""CREATE TABLE node_enrollments (
                id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL, expires INTEGER NOT NULL, used INTEGER,
                request_hash TEXT, response TEXT,
                created INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE node_certificates (
                fingerprint TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                serial TEXT UNIQUE NOT NULL, expires INTEGER NOT NULL, grace_until INTEGER,
                revoked INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)""")
            db.execute(
                "CREATE INDEX node_certificates_node ON node_certificates(node_id)"
            )
            set_schema_version(db, 7)
        if version < 8:
            db.execute(
                "ALTER TABLE users ADD COLUMN quota_mode TEXT NOT NULL DEFAULT 'legacy' CHECK(quota_mode IN ('legacy','lease'))"
            )
            db.execute("ALTER TABLE counters ADD COLUMN lease_id TEXT")
            db.execute("""CREATE TABLE budget_leases (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                period_no INTEGER NOT NULL, instance TEXT NOT NULL,
                granted INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0,
                expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0,
                created INTEGER NOT NULL, updated INTEGER NOT NULL,
                UNIQUE(user_id,node_id,period_no,instance))""")
            db.execute(
                "CREATE INDEX budget_leases_user_period ON budget_leases(user_id,period_no,closed)"
            )
            set_schema_version(db, 8)
        if version < 9:
            db.execute("""CREATE TABLE dns_policies (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                revision TEXT NOT NULL, rules TEXT NOT NULL,
                created INTEGER NOT NULL, updated INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE dns_accounts (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                policy_id TEXT NOT NULL REFERENCES dns_policies(id),
                token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
                query_limit INTEGER NOT NULL DEFAULT 0, qps INTEGER NOT NULL DEFAULT 20,
                period_no INTEGER NOT NULL DEFAULT 0,
                created INTEGER NOT NULL, updated INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE dns_periods (
                account_id TEXT NOT NULL REFERENCES dns_accounts(id) ON DELETE CASCADE,
                period_no INTEGER NOT NULL, queries INTEGER NOT NULL DEFAULT 0,
                request_bytes INTEGER NOT NULL DEFAULT 0, response_bytes INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
                created INTEGER NOT NULL, closed INTEGER,
                PRIMARY KEY(account_id,period_no))""")
            db.execute("""CREATE TABLE dns_ip_leases (
                ip TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES dns_accounts(id) ON DELETE CASCADE,
                expires INTEGER NOT NULL, created INTEGER NOT NULL)""")
            db.execute(
                "CREATE INDEX dns_ip_leases_account ON dns_ip_leases(account_id)"
            )
            db.execute("""CREATE TABLE dns_rate (
                account_id TEXT PRIMARY KEY REFERENCES dns_accounts(id) ON DELETE CASCADE,
                window_started INTEGER NOT NULL, requests INTEGER NOT NULL)""")
            set_schema_version(db, 9)
        if version < 10:
            db.execute("""CREATE TABLE doctor_imports (
                id TEXT PRIMARY KEY, source_instance TEXT NOT NULL UNIQUE,
                fingerprint TEXT NOT NULL, source_revision TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('staged','rolled_back')),
                summary TEXT NOT NULL, payload TEXT NOT NULL,
                backup_path TEXT NOT NULL, created INTEGER NOT NULL, reverted INTEGER)""")
            db.execute("""CREATE TABLE doctor_import_users (
                import_id TEXT NOT NULL REFERENCES doctor_imports(id),
                external_id INTEGER NOT NULL, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
                quota_bytes INTEGER NOT NULL, used_bytes INTEGER NOT NULL,
                source_status TEXT NOT NULL, period_mode TEXT NOT NULL,
                reset_at INTEGER, expires INTEGER, guard_hash TEXT NOT NULL,
                PRIMARY KEY(import_id,external_id))""")
            db.execute("""CREATE TABLE doctor_import_templates (
                import_id TEXT NOT NULL REFERENCES doctor_imports(id),
                external_id INTEGER NOT NULL, name TEXT NOT NULL, is_default INTEGER NOT NULL,
                selections TEXT NOT NULL, exclusions TEXT NOT NULL, custom_domains TEXT NOT NULL,
                PRIMARY KEY(import_id,external_id))""")
            set_schema_version(db, 10)


def encrypt_legacy_mfa(db):
    from .secrets import PREFIX, seal

    for row in db.execute("SELECT username,secret FROM admin_mfa").fetchall():
        if not row["secret"].startswith(PREFIX):
            db.execute(
                "UPDATE admin_mfa SET secret=? WHERE username=?",
                (seal(row["secret"]), row["username"]),
            )


def migrate_to_v4(db):
    """Monthly usage periods. Existing users keep unlimited-period behaviour."""
    db.execute(
        "ALTER TABLE users ADD COLUMN period TEXT NOT NULL DEFAULT 'none' "
        "CHECK(period IN ('none','monthly'))"
    )
    db.execute("ALTER TABLE users ADD COLUMN period_days INTEGER NOT NULL DEFAULT 30")
    # Starts on the first recorded usage, not at creation: a new user does not lose
    # the first days of the cycle while the device is not yet connected.
    db.execute("ALTER TABLE users ADD COLUMN period_start INTEGER")
    db.execute("ALTER TABLE users ADD COLUMN period_no INTEGER NOT NULL DEFAULT 0")


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
