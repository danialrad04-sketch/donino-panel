import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def db_path():
    return Path(os.environ.get('DONINO_DB', 'data/donino.db'))


@contextmanager
def database():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = sqlite3.connect(path, timeout=20)
    os.chmod(path, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA busy_timeout=20000')
    try:
        # Serialize read-modify-write operations across requests/workers.
        connection.execute('BEGIN IMMEDIATE')
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize():
    with database() as db:
        db.executescript('''
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
        ''')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return salt + ':' + hashed.hex()


def verify_password(password, stored):
    salt, expected = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return hmac.compare_digest(actual.hex(), expected)


def audit(db, actor, action, target=''):
    db.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',
               (int(time.time()), actor, action, target))
