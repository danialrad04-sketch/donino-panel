"""Native optional monitor preflight; safe to import before pip bootstrap."""

import grp
import hashlib
import os
import subprocess
from pathlib import Path

from app import tunnel_probe
from .common import InstallError, read_env

UNIT = Path("/etc/systemd/system/donino-tunnel-monitor.service")


def options(args, state, config=Path("/etc/donino/panel.env")):
    if (
        UNIT.exists()
        and state.get("managed_files", {}).get(str(UNIT))
        != hashlib.sha256(UNIT.read_bytes()).hexdigest()
    ):
        raise InstallError(
            "Refusing to overwrite an unmanaged or modified tunnel monitor unit"
        )
    if args.without_tunnel_monitor:
        return False
    if not (args.with_tunnel_monitor or state.get("tunnel_monitor")):
        return False
    if not config.is_file():
        raise InstallError(
            "Install control first and configure the tunnel bridge/verifier in panel.env"
        )
    values = read_env(config)
    previous = dict(os.environ)
    try:
        grp.getgrnam("donino-link")
        if any(
            not values.get(key)
            for key in (
                "DONINO_TUNNEL_PROBE_MIHOMO",
                "DONINO_TUNNEL_PROBE_URL",
                "DONINO_TUNNEL_PROBE_SHA256",
            )
        ):
            raise ValueError("missing persisted verifier settings")
        for key in tuple(os.environ):
            if key.startswith("DONINO_TUNNEL_PROBE_"):
                del os.environ[key]
        os.environ.update(values)
        if values.get("DONINO_TUNNEL_BRIDGE") != "1":
            raise ValueError("bridge disabled")
        tunnel_probe.configuration_revision()
        binary = tunnel_probe.configuration()[0]
        result = subprocess.run(
            ["runuser", "-u", "donino", "--", binary, "-v"],
            capture_output=True,
            timeout=10,
        )
        if (
            result.returncode
            or tunnel_probe.VERSION.encode() not in result.stdout[:4096]
        ):
            raise ValueError("unavailable verifier")
        subprocess.run(
            [
                "runuser",
                "-u",
                "donino",
                "--",
                "/opt/donino-panel/current/.venv/bin/python",
                "-c",
                "from pathlib import Path; from app.tunnel_probe import configuration; "
                "c=configuration(); assert not c[3] or len(Path(c[3]).read_bytes())<=1048576",
            ],
            cwd="/opt/donino-panel/current",
            env={**os.environ, **values},
            capture_output=True,
            timeout=10,
            check=True,
        )
    except (
        KeyError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        tunnel_probe.ProbeError,
    ):
        raise InstallError(
            "Tunnel monitor requires donino-link, enabled bridge and the pinned accessible verifier configuration"
        ) from None
    finally:
        os.environ.clear()
        os.environ.update(previous)
    return True
