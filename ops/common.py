import json
import os
import subprocess
import tempfile
from pathlib import Path


class InstallError(RuntimeError):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".donino-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            os.fchmod(file.fileno(), mode)
            file.write(content.encode() if isinstance(content, str) else content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(arguments, *, input=None, capture=False, code=6, env=None, cwd=None):
    result = subprocess.run(
        arguments, input=input, text=True, capture_output=capture, env=env, cwd=cwd
    )
    if result.returncode:
        # Do not echo argv, stdin or process output: they can carry credentials.
        raise InstallError(
            f"{Path(arguments[0]).name} failed (exit {result.returncode}); inspect the service/package logs",
            code,
        )
    return result.stdout if capture else ""


def read_env(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if not key.replace("_", "").isalnum() or any(
                c in value for c in "\r\n\x00"
            ):
                raise InstallError("Invalid environment file")
            result[key] = value
    return result


def save_state(path, state):
    atomic_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
