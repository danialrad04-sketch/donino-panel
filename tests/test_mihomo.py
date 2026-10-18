"""Real Mihomo client acceptance for six TLS profiles.

Opt-in, because it needs both binaries:
    DONINO_TEST_XRAY=/path/to/xray DONINO_TEST_MIHOMO=/path/to/mihomo \
        python -m unittest discover -s tests -p test_mihomo.py -v

The panel, node agent and node Xray are real. The client profiles are taken
from the panel's Mihomo/Clash subscription output (`/sub/{token}?format=clash`).
The only lab changes are: a local SOCKS listener, a single-proxy selection,
an explicit trust for the test CA (`ca`), and, for negative controls only, a
different `servername`. No skip-cert-verify, no allowInsecure, and no
hand-written proxy body.

Profiles: VLESS WS+TLS, VLESS gRPC+TLS, VMess WS+TLS, VMess gRPC+TLS,
Trojan TCP+TLS and Trojan WS+TLS. REALITY, sing-box and v2rayN are out of scope.
"""

import contextlib
import copy
import importlib.util
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import sys
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from agent.main import NodeAgent
from app.db import database, hash_password
from app.main import app
from support import configure
from test_xray_transports import (
    MARKER,
    _EchoHandler,
    _LocalPanel,
    _free_port,
    _socks_connect,
    _write_test_pki,
)

SIX_PROFILES = [
    ("vless", "ws"),
    ("vless", "grpc"),
    ("vmess", "ws"),
    ("vmess", "grpc"),
    ("trojan", "tcp"),
    ("trojan", "ws"),
]
TROJAN = [p for p in SIX_PROFILES if p[0] == "trojan"]
# Regression signature when the historical Trojan SNI export is reintroduced.
DEFECT_SIGNATURE = "cannot validate certificate for 127.0.0.1"
UNKNOWN_AUTHORITY = "x509: certificate signed by unknown authority"
WRONG_HOSTNAME = "not wrong.example"
DEFAULT_CA = object()


def _label(protocol, transport, device):
    return f" · {protocol}-{transport} · {device} · "


class _Mihomo:
    """Starts one real Mihomo client per profile, on loopback only, and tears it down."""

    def __init__(self, binary, folder, processes):
        self.binary = binary
        self.folder = folder
        self.processes = processes
        self.count = 0
        self.ca_path = None

    def run(self, proxy, ca=DEFAULT_CA, server_name=None):
        """Return (body, log). body is b'' if the transfer failed.

        Trust is explicit: Go's root pool for this process is replaced with the
        test CA through SSL_CERT_FILE. With ca=None no test CA is trusted.
        """
        self.count += 1
        directory = self.folder / f"mihomo-{self.count}"
        directory.mkdir()
        socks = _free_port()
        entry = copy.deepcopy(proxy)  # the subscription body, unmodified
        trust = self.ca_path if ca is DEFAULT_CA else ca
        env = {k: v for k, v in os.environ.items() if k != "SSL_CERT_FILE"}
        if trust is not None:
            env["SSL_CERT_FILE"] = str(trust)
        if server_name is not None:
            entry["sni" if entry["type"] == "trojan" else "servername"] = server_name
        config = {
            "socks-port": socks,
            "bind-address": "127.0.0.1",
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "ipv6": False,
            "geo-auto-update": False,
            "geodata-mode": False,
            "proxies": [entry],
            "proxy-groups": [
                {"name": "Donino", "type": "select", "proxies": [entry["name"]]}
            ],
            "rules": ["MATCH,Donino"],
        }
        path = directory / "config.yaml"
        path.write_text(json.dumps(config, ensure_ascii=False))
        checked = subprocess.run(
            [self.binary, "-d", str(directory), "-f", str(path), "-t"],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        if checked.returncode != 0:
            raise AssertionError(
                "Mihomo rejected the config:\n" + checked.stdout + checked.stderr
            )
        log = directory / "mihomo.log"
        ready_file = directory / "running"
        with open(log, "w") as handle:
            proc = subprocess.Popen(
                [
                    self.binary,
                    "-d",
                    str(directory),
                    "-f",
                    str(path),
                    "-post-up",
                    shlex.join(["/usr/bin/touch", str(ready_file)]),
                ],
                stdout=handle,
                stderr=subprocess.STDOUT,
                env=env,
            )
        self.processes.append(proc)
        try:
            ready = False
            for _ in range(100):
                if proc.poll() is not None:
                    break
                # The pinned engine opens SOCKS and logs provider startup while
                # tunnel.Status is still Inner. It can acknowledge SOCKS then
                # silently drop application data until OnRunning, after GC.
                # Its fixed post-up hook runs only after that transition; no
                # untrusted input is interpolated into this fixture command.
                if not ready_file.exists():
                    time.sleep(0.05)
                    continue
                try:
                    with socket.create_connection(("127.0.0.1", socks), timeout=0.1):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.05)
            if not ready:
                raise AssertionError(
                    "Mihomo did not reach its post-up running state: "
                    + log.read_text(errors="replace")[-1200:]
                )
            body = b""
            failure = ""
            try:
                with socket.create_connection(("127.0.0.1", socks), timeout=15) as sock:
                    _socks_connect(sock, self.echo_port)
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    while chunk := sock.recv(65536):
                        body += chunk
            except OSError as error:
                body = b""
                failure = str(error)
            if not body:
                # A socket error may arrive before the outbound goroutine logs
                # the TLS refusal. Preserve that required diagnostic before exit.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    text = log.read_text(errors="replace")
                    if "x509:" in text or "[TCP]" in text:
                        break
                    time.sleep(0.02)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        text = log.read_text(errors="replace")
        if failure:
            text += "\nLab client socket error: " + failure
        # Isolation guard: every destination Mihomo dialled must be the loopback test node or echo.
        for target in re.findall(r"-->\s+(\S+)", text):
            if not target.startswith("127.0.0.1:"):
                raise AssertionError(f"Mihomo dialled a non-loopback target: {target}")
        return body, text


class _Fixture:
    def __init__(self, panel, agent, mihomo, echo_port):
        self.panel = panel
        self.agent = agent
        self.mihomo = mihomo
        self.echo_port = echo_port

    def new_user(self, name):
        return self.panel.post("/api/users", json={"name": name}).json()

    def token(self, uid):
        with database() as db:
            return db.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()[
                0
            ]

    def devices(self, uid):
        return self.panel.get(f"/api/users/{uid}/devices").json()

    def default_device(self, uid):
        return next(row["name"] for row in self.devices(uid) if row["is_default"])

    def clash(self, token):
        response = self.panel.get(f"/sub/{token}?format=clash")
        if response.status_code != 200:
            raise AssertionError(f"clash subscription returned {response.status_code}")
        return response.json()

    @staticmethod
    def proxy(clash, protocol, transport, device):
        for proxy in clash["proxies"]:
            if _label(protocol, transport, device) in proxy["name"]:
                return proxy
        raise AssertionError(
            f"no Mihomo profile for {protocol}/{transport} on {device}"
        )


@contextlib.contextmanager
def _fixture(xray, mihomo_bin, folder, processes):
    old = dict(os.environ)
    http = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    agent = None
    try:
        configure(folder)
        os.environ.update(
            DONINO_SECURE_COOKIE="false",
            DONINO_PANEL_URL="http://127.0.0.1:8000",
            DONINO_NODE_STATE=str(folder / "node"),
            DONINO_XRAY=xray,
        )
        ca_path, cert_path, key_path = _write_test_pki(folder / "pki")
        with TestClient(app) as panel:
            with database() as db:
                db.execute(
                    "INSERT INTO admins VALUES(?,?,?)",
                    ("admin", hash_password("test-password-long"), "owner"),
                )
            panel.headers["X-Donino"] = "1"
            if (
                panel.post(
                    "/api/login",
                    json={"username": "admin", "password": "test-password-long"},
                ).status_code
                != 200
            ):
                raise AssertionError("owner login failed")
            node = panel.post(
                "/api/nodes", json={"name": "edge", "host": "127.0.0.1"}
            ).json()
            os.environ["DONINO_NODE_TOKEN"] = node["token"]
            for protocol, transport in SIX_PROFILES:
                response = panel.post(
                    "/api/inbounds",
                    json={
                        "node_id": node["id"],
                        "name": f"{protocol}-{transport}",
                        "protocol": protocol,
                        "transport": transport,
                        "port": _free_port(),
                        "sni": "localhost",
                        "path": "/donino-ws",
                        "service_name": f"svc-{protocol}-{transport}",
                        "cert_file": str(cert_path),
                        "key_file": str(key_path),
                    },
                )
                if response.status_code != 201:
                    raise AssertionError(response.text)
            agent = NodeAgent()
            agent.client.close()
            agent.client = _LocalPanel(panel, node["token"])
            agent.tick()
            mihomo = _Mihomo(mihomo_bin, folder, processes)
            mihomo.ca_path = ca_path
            mihomo.echo_port = http.server_port
            yield _Fixture(panel, agent, mihomo, http.server_port)
    finally:
        if agent:
            agent.close()
        for proc in processes:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
        os.environ.clear()
        os.environ.update(old)


def _load_fetcher():
    path = Path(__file__).resolve().parents[1] / "scripts" / "fetch_mihomo.py"
    spec = importlib.util.spec_from_file_location("fetch_mihomo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MihomoFetcherTest(unittest.TestCase):
    def test_pinned_version_asset_and_digest(self):
        fetch = _load_fetcher()
        self.assertEqual(fetch.VERSION, "v1.19.32")
        self.assertEqual(fetch.ASSET, "mihomo-linux-amd64-compatible-v1.19.32.gz")
        self.assertEqual(
            fetch.SHA256,
            "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20",
        )
        self.assertTrue(
            fetch.URL.startswith(
                "https://github.com/MetaCubeX/mihomo/releases/download/"
            )
        )

    def test_digest_mismatch_refuses_to_extract(self):
        fetch = _load_fetcher()
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "out"
            with (
                mock.patch.object(
                    fetch, "_download", return_value=(b"not gzip", "0" * 64)
                ),
                mock.patch.object(platform, "system", return_value="Linux"),
                mock.patch.object(platform, "machine", return_value="x86_64"),
                mock.patch.object(sys, "argv", ["fetch_mihomo.py", str(destination)]),
            ):
                with self.assertRaises(SystemExit) as raised:
                    fetch.main()
            self.assertIn("SHA-256 mismatch", str(raised.exception))
            self.assertFalse((destination / "mihomo").exists())


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_XRAY") and os.environ.get("DONINO_TEST_MIHOMO"),
    "Set DONINO_TEST_XRAY and DONINO_TEST_MIHOMO for real client acceptance",
)
class MihomoAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.xray = os.path.abspath(os.environ["DONINO_TEST_XRAY"])
        self.mihomo = os.path.abspath(os.environ["DONINO_TEST_MIHOMO"])
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.processes = []

    def tearDown(self):
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self._tmp.cleanup()

    def test_binary_is_the_pinned_version(self):
        output = subprocess.run(
            [self.mihomo, "-v"], capture_output=True, text=True, timeout=30
        ).stdout
        self.assertIn("Mihomo Meta v1.19.32", output)

    def test_all_six_profiles_transfer_through_real_mihomo(self):
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-user")
            lab.agent.tick()
            clash = lab.clash(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            self.assertEqual(len(clash["proxies"]), 6)
            for protocol, transport in SIX_PROFILES:
                proxy = lab.proxy(clash, protocol, transport, default)
                body, log = lab.mihomo.run(proxy)
                self.assertIn(
                    MARKER,
                    body,
                    f"{protocol}/{transport} did not transfer. Log:\n{log[-800:]}",
                )
                print(
                    f"  Mihomo {protocol}/{transport}: transfer passed ({len(body)} bytes)"
                )

    def test_wrong_ca_is_refused_with_a_certificate_error_for_all_six(self):
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-tls")
            lab.agent.tick()
            clash = lab.clash(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            other_ca, _, _ = _write_test_pki(self.folder / "other-pki")
            for protocol, transport in SIX_PROFILES:
                proxy = lab.proxy(clash, protocol, transport, default)
                body, log = lab.mihomo.run(proxy, ca=other_ca)
                self.assertNotIn(
                    MARKER, body, f"{protocol}/{transport} accepted an untrusted CA"
                )
                self.assertIn(
                    UNKNOWN_AUTHORITY,
                    log,
                    f"{protocol}/{transport}: refusal was not an untrusted-CA error. Log:\n{log[-800:]}",
                )
                print(
                    f"  Mihomo {protocol}/{transport}: untrusted CA refused (unknown authority)"
                )

    def test_wrong_hostname_is_refused_for_all_six_profiles(self):
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-host")
            lab.agent.tick()
            clash = lab.clash(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            for protocol, transport in SIX_PROFILES:
                proxy = lab.proxy(clash, protocol, transport, default)
                body, _ = lab.mihomo.run(proxy)
                self.assertIn(
                    MARKER, body, f"{protocol}/{transport} valid profile failed"
                )
                body, log = lab.mihomo.run(proxy, server_name="wrong.example")
                self.assertNotIn(
                    MARKER, body, f"{protocol}/{transport} accepted a wrong hostname"
                )
                self.assertIn(
                    WRONG_HOSTNAME,
                    log,
                    f"{protocol}/{transport}: refusal was not a wrong-hostname error. Log:\n{log[-800:]}",
                )
                print(
                    f"  Mihomo {protocol}/{transport}: wrong hostname refused (certificate not valid for wrong.example)"
                )

    def test_legacy_trojan_sni_regression_is_rejected(self):
        """The actual export works; moving SNI back to its historical key fails."""
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-defect")
            lab.agent.tick()
            clash = lab.clash(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            for protocol, transport in TROJAN:
                proxy = lab.proxy(clash, protocol, transport, default)
                self.assertEqual(proxy.get("sni"), "localhost")
                self.assertNotIn("servername", proxy)
                body, _ = lab.mihomo.run(proxy)
                self.assertIn(MARKER, body)
                legacy = dict(proxy)
                legacy["servername"] = legacy.pop("sni")
                body, log = lab.mihomo.run(legacy)
                self.assertNotIn(MARKER, body)
                self.assertIn(
                    DEFECT_SIGNATURE,
                    log,
                    f"{protocol}/{transport}: failure is not the known servername defect. Log:\n{log[-800:]}",
                )
                print(
                    f"  {protocol}/{transport}: real export works, legacy wrong-SNI export rejected"
                )

    def test_trojan_profiles_transfer_without_export_rewriting(self):
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-trojan")
            lab.agent.tick()
            clash = lab.clash(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            for protocol, transport in TROJAN:
                body, log = lab.mihomo.run(
                    lab.proxy(clash, protocol, transport, default)
                )
                self.assertIn(
                    MARKER,
                    body,
                    f"{protocol}/{transport} did not transfer. Log:\n{log[-400:]}",
                )

    def test_device_bytes_and_cut_off_with_mihomo(self):
        with _fixture(self.xray, self.mihomo, self.folder, self.processes) as lab:
            user = lab.new_user("mihomo-device")
            second = lab.panel.post(
                f"/api/users/{user['id']}/devices", json={"name": "second-phone"}
            ).json()
            lab.agent.tick()
            token = lab.token(user["id"])
            clash = lab.clash(token)
            default = lab.default_device(user["id"])
            stale = {}
            for protocol, transport in SIX_PROFILES:
                proxy = lab.proxy(clash, protocol, transport, "second-phone")
                stale[(protocol, transport)] = proxy
                body, _ = lab.mihomo.run(proxy)
                self.assertIn(
                    MARKER, body, f"{protocol}/{transport} second device failed"
                )
                body, _ = lab.mihomo.run(lab.proxy(clash, protocol, transport, default))
                self.assertIn(
                    MARKER, body, f"{protocol}/{transport} default device failed"
                )

            lab.agent.tick()
            rows = {d["name"]: d for d in lab.devices(user["id"])}
            for name in (default, "second-phone"):
                self.assertGreater(
                    rows[name]["uploaded"] + rows[name]["downloaded"],
                    0,
                    f"no bytes for {name}",
                )
            periods = lab.panel.get(f"/api/users/{user['id']}/periods").json()
            self.assertGreater(sum(p["uploaded"] + p["downloaded"] for p in periods), 0)
            print("  Mihomo traffic reached both device IDs and the current period")

            lab.panel.put(
                f"/api/devices/{second['id']}",
                json={"name": "second-phone", "enabled": False},
            )
            lab.agent.tick()
            fresh = lab.clash(token)
            self.assertFalse(
                any(" · second-phone · " in p["name"] for p in fresh["proxies"]),
                "disabled device still appears in the fresh subscription",
            )
            for protocol, transport in SIX_PROFILES:
                body, log = lab.mihomo.run(stale[(protocol, transport)])
                self.assertNotIn(
                    MARKER,
                    body,
                    f"{protocol}/{transport} stale second-device profile still works",
                )
                body, _ = lab.mihomo.run(lab.proxy(fresh, protocol, transport, default))
                self.assertIn(
                    MARKER, body, f"{protocol}/{transport} default device stopped"
                )
            print(
                "  Disabled device: stored Mihomo profiles stopped on all six profiles; default device kept working"
            )


if __name__ == "__main__":
    unittest.main()
