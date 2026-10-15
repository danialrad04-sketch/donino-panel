"""TOTP (RFC 6238), encrypted seeds and one-use recovery codes."""

import base64
import fcntl
import hashlib
import hmac
import os
import secrets
import struct
import time
from pathlib import Path

from cryptography.fernet import Fernet

from .db import db_path, digest


def key_path():
    return Path(os.environ.get("DONINO_KEY_FILE", str(db_path().parent / "master.key")))


def cipher():
    path = key_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        if os.fstat(file.fileno()).st_mode & 0o077:
            raise RuntimeError(
                "Master key permissions must be 0600; refusing insecure key"
            )
        key = file.read()
        if not key:
            key = Fernet.generate_key()
            file.write(key)
            file.flush()
            os.fsync(file.fileno())
        return Fernet(key)


def totp(secret, step=None):
    step = int(time.time()) // 30 if step is None else step
    key = base64.b32decode(secret + "=" * ((-len(secret)) % 8))
    value = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = value[-1] & 15
    number = struct.unpack(">I", value[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(db, row, code, *, now=None):
    if not code or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    now = time.time() if now is None else now
    seed = cipher().decrypt(row["secret"].encode()).decode()
    for step in (int(now) // 30 - 1, int(now) // 30, int(now) // 30 + 1):
        if step > row["last_step"] and hmac.compare_digest(totp(seed, step), code):
            db.execute(
                "UPDATE admin_mfa SET last_step=? WHERE username=?",
                (step, row["username"]),
            )
            return True
    return False


def verify_factor(db, username, code="", recovery=""):
    db.lock("mfa:" + username)
    row = db.execute(
        "SELECT * FROM admin_mfa WHERE username=? AND enabled=1", (username,)
    ).fetchone()
    if not row:
        return True
    if recovery:
        result = db.execute(
            "DELETE FROM recovery_codes WHERE username=? AND digest=?",
            (username, digest(recovery)),
        )
        return result.rowcount == 1
    return verify_totp(db, row, code)


def new_recovery_codes(db, username):
    db.execute("DELETE FROM recovery_codes WHERE username=?", (username,))
    codes = [secrets.token_hex(8) for _ in range(10)]
    for code in codes:
        db.execute(
            "INSERT INTO recovery_codes(digest,username) VALUES(?,?)",
            (digest(code), username),
        )
    return codes
