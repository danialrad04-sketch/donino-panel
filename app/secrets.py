"""Encryption at rest for MFA seeds; keep the master key outside database backups."""

import fcntl
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet

from .db import db_path

PREFIX = "fernet:"


def key_path():
    return Path(os.environ.get("DONINO_KEY_FILE", str(db_path().parent / "master.key")))


def cipher(*, create=False):
    path = key_path()
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b" if create else "rb") as file:
        fcntl.flock(file, fcntl.LOCK_EX if create else fcntl.LOCK_SH)
        mode = os.fstat(file.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise RuntimeError("Master key must be a private regular file (0600)")
        key = file.read()
        if not key and create:
            key = Fernet.generate_key()
            file.write(key)
            file.flush()
            os.fsync(file.fileno())
        return Fernet(key)


def seal(value):
    return PREFIX + cipher(create=True).encrypt(value.encode()).decode()


def unseal(value):
    if not value.startswith(PREFIX):
        raise ValueError("Unencrypted MFA seed; migrate the database first")
    return cipher().decrypt(value[len(PREFIX) :].encode()).decode()
