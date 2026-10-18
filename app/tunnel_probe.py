"""Bounded real-client acceptance. All destinations/trust are operator configured.

No request supplies a binary, URL, CA, command or proxy credential. The caller
provides profiles compiled from the DB. This module never persists a receipt.
"""

import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "v1.19.32"
MAX_BODY = 65536
TOTAL_SECONDS = 90
SOCKET_SECONDS = 8


class ProbeError(Exception):
    """Only fixed error codes may cross the public API boundary."""


def configuration():
    binary = Path(os.environ.get("DONINO_TUNNEL_PROBE_MIHOMO", ""))
    url = os.environ.get("DONINO_TUNNEL_PROBE_URL", "")
    digest = os.environ.get("DONINO_TUNNEL_PROBE_SHA256", "")
    ca = os.environ.get("DONINO_TUNNEL_PROBE_CA", "")
    try:
        target = urlsplit(url)
        valid = (
            binary.is_absolute()
            and binary.is_file()
            and os.access(binary, os.X_OK)
            and target.scheme == "https"
            and target.hostname
            and not target.username
            and not target.password
            and not target.query
            and not target.fragment
            and (target.port is None or 1 <= target.port <= 65535)
            and len(url) <= 2048
            and not re.search(r"[\s\x00-\x1f\x7f]", url)
            and re.fullmatch(r"[a-f0-9]{64}", digest)
            and (not ca or (Path(ca).is_absolute() and Path(ca).is_file()))
        )
    except (OSError, ValueError):
        valid = False
    if not valid:
        raise ProbeError("probe_not_configured")
    return str(binary), target, digest, ca


def available():
    try:
        configuration()
        return True
    except ProbeError:
        return False


def _exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProbeError("probe_connection_closed")
        data += chunk
    return data


def _response(port, target, ca, deadline, auth=None):
    # SOCKS remote-name resolution ensures the target is reached through the
    # selected VPN proxy. There is no DIRECT rule or automatic HTTP redirect.
    response_deadline = min(deadline, time.monotonic() + SOCKET_SECONDS)
    timeout = response_deadline - time.monotonic()
    if timeout <= 0:
        raise ProbeError("probe_deadline")
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    current = [sock]
    interrupted = threading.Event()

    def interrupt():
        interrupted.set()
        try:
            current[0].shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    watchdog = threading.Timer(max(0, response_deadline - time.monotonic()), interrupt)
    watchdog.daemon = True
    watchdog.start()
    try:
        method = b"\x02" if auth else b"\x00"
        sock.sendall(b"\x05\x01" + method)
        if _exact(sock, 2) != b"\x05" + method:
            raise ProbeError("probe_socks_rejected")
        if auth:
            username, password = (value.encode() for value in auth)
            sock.sendall(
                b"\x01"
                + bytes([len(username)])
                + username
                + bytes([len(password)])
                + password
            )
            if _exact(sock, 2) != b"\x01\x00":
                raise ProbeError("probe_socks_rejected")
        host = target.hostname.encode("idna")
        if len(host) > 255:
            raise ProbeError("probe_not_configured")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host)])
            + host
            + (target.port or 443).to_bytes(2, "big")
        )
        reply = _exact(sock, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise ProbeError("probe_socks_rejected")
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = _exact(sock, 1)[0]
        if size is None:
            raise ProbeError("probe_socks_rejected")
        _exact(sock, size + 2)
        context = ssl.create_default_context(cafile=ca or None)
        sock.settimeout(max(0.01, response_deadline - time.monotonic()))
        sock = context.wrap_socket(sock, server_hostname=target.hostname)
        current[0] = sock
        connection = http.client.HTTPConnection(target.hostname, target.port or 443)
        connection.sock = sock
        try:
            connection.request(
                "GET",
                target.path or "/",
                headers={
                    "Connection": "close",
                    "Cache-Control": "no-cache",
                    "Accept-Encoding": "identity",
                    "User-Agent": "Donino-Tunnel-Probe/1",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ProbeError("probe_http_rejected")
            body = response.read(MAX_BODY + 1)
            if interrupted.is_set() or time.monotonic() >= response_deadline:
                raise ProbeError("probe_deadline")
            if response.length not in (None, 0):
                raise ProbeError("probe_incomplete_response")
            if not body:
                raise ProbeError("probe_empty_response")
            if len(body) > MAX_BODY:
                raise ProbeError("probe_response_too_large")
            return hashlib.sha256(body).hexdigest()
        finally:
            connection.close()
    finally:
        watchdog.cancel()
        sock.close()


def run(proxies):
    binary, target, expected, ca = configuration()
    if not 1 <= len(proxies) <= 8:
        raise ProbeError("probe_profile_limit")
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        version = subprocess.run(
            [binary, "-v"], capture_output=True, text=True, timeout=5, check=True
        ).stdout
        if "Mihomo Meta " + VERSION + " " not in version:
            raise ProbeError("probe_engine_version")
        for proxy in proxies:
            with tempfile.TemporaryDirectory(prefix="donino-vpn-probe-") as folder:
                root = Path(folder)
                # Loopback only, private temporary credentials, no controller,
                # providers, automatic geodata updates or shell input from DB.
                with socket.socket() as reserved:
                    reserved.bind(("127.0.0.1", 0))
                    port = reserved.getsockname()[1]
                profile = {**proxy, "name": "DoninoProbe"}
                auth = (secrets.token_hex(16), secrets.token_hex(16))
                config = {
                    "socks-port": port,
                    "bind-address": "127.0.0.1",
                    "allow-lan": False,
                    "mode": "rule",
                    "log-level": "silent",
                    "ipv6": False,
                    "geo-auto-update": False,
                    "geodata-mode": False,
                    "proxies": [profile],
                    "authentication": [":".join(auth)],
                    "skip-auth-prefixes": [],
                    "rules": ["MATCH,DoninoProbe"],
                }
                path, ready = root / "config.json", root / "running"
                path.touch(mode=0o600)
                path.write_text(json.dumps(config))
                env = dict(os.environ)
                if ca:
                    env["SSL_CERT_FILE"] = ca
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(__file__).with_name("probe_runner.py")),
                        "--parent",
                        str(os.getpid()),
                        binary,
                        "-d",
                        folder,
                        "-f",
                        str(path),
                        "-post-up",
                        shlex.join(["/usr/bin/touch", str(ready)]),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                try:
                    startup = min(deadline, time.monotonic() + 5)
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic() >= startup:
                            raise ProbeError("probe_engine_startup")
                        time.sleep(0.03)
                    actual = _response(port, target, ca, deadline, auth)
                    if not hmac.compare_digest(actual, expected):
                        raise ProbeError("probe_payload_mismatch")
                    if time.monotonic() > deadline:
                        raise ProbeError("probe_deadline")
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
        return {"engine": "mihomo", "version": VERSION, "profiles": len(proxies)}
    except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError):
        # TLS/socket/engine exceptions can contain private addresses or paths.
        raise ProbeError("probe_transfer_failed") from None
