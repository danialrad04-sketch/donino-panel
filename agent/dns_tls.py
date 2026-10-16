"""Receive a verified DoT certificate through stdin as the unprivileged user."""

import json
import hashlib
import os
import shutil
import ssl
import sys
import uuid
from pathlib import Path

from ops.common import atomic_write


def install(directory, material):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Refusing a symbolic TLS directory")
    directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    version = directory / (
        "pair-" + hashlib.sha256(material["panel.crt"].encode()).hexdigest()[:32]
    )
    fresh = not version.exists()
    if version.is_symlink():
        raise ValueError("Refusing a symbolic TLS identity")
    try:
        if fresh:
            version.mkdir(mode=0o700)
            for name in ("panel.crt", "panel.key"):
                atomic_write(version / name, material[name])
        elif any(
            (version / name).read_text() != material[name]
            for name in ("panel.crt", "panel.key")
        ):
            raise ValueError("Existing certificate identity has different material")
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            version / "panel.crt", version / "panel.key"
        )
    except BaseException:
        if fresh:
            shutil.rmtree(version)
        raise
    pointer = directory / (".current-" + uuid.uuid4().hex)
    try:
        pointer.symlink_to(version.name)
        os.replace(pointer, directory / "current")
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        pointer.unlink(missing_ok=True)


def main():
    install(sys.argv[1], json.loads(sys.stdin.read(1_000_000)))


if __name__ == "__main__":
    main()
