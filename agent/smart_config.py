"""Install private exit config through stdin as the unprivileged role user."""

import json
import sys
from pathlib import Path

from ops.common import atomic_write
from .smart_exit import ExitServer


def install(path, config):
    ExitServer(config)  # Validate the domain allowlist before replacing the file.
    atomic_write(Path(path), json.dumps(config) + "\n", 0o600)


if __name__ == "__main__":
    install(sys.argv[1], json.loads(sys.stdin.read(1_000_000)))
