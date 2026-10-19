"""AEAD and multi-user 2022 acceptance using unmodified panel exports.

Real paths require DONINO_TEST_XRAY; Mihomo acceptance additionally requires
DONINO_TEST_MIHOMO. No production target, route or firewall is modified.
"""

import base64
import contextlib
import copy
import json
import http.client
import os
import socket
import socketserver
import subprocess
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit
from unittest.mock import patch

from agent.main import NodeAgent
from app.core import compile_config
from app.db import database
from app.shadowsocks import METHODS, device_key
from app.secrets import unseal
from test_accounts import PanelBase
from test_xray_transports import (
    MARKER,
    _EchoHandler,
    _LocalPanel,
    _free_port,
    _socks_connect,
)
from http.server import ThreadingHTTPServer


def decode_link(link):
    url = urlsplit(link)
    if url.password is not None:
        method, password = unquote(url.username), unquote(url.password)
    else:
        encoded = url.username
        method, password = (
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            .decode()
            .split(":", 1)
        )
    return {
        "name": unquote(url.fragment),
        "type": "ss",
        "server": url.hostname,
        "port": url.port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


class ShadowsocksFixture(PanelBase):
    def setUp(self):
        super().setUp()
        self.node = self.post("/nodes", {"name": "ss-edge", "host": "127.0.0.1"}).json()
        self.endpoints = []
        # Keep all chosen TCP ports bound until the inventory is built. Closing
        # each ephemeral reservation immediately lets the OS return the same
        # number for a later cipher, which correctly causes API 409.
        with contextlib.ExitStack() as reservations:
            for method in METHODS:
                reserved = reservations.enter_context(socket.socket())
                reserved.bind(("127.0.0.1", 0))
                body = {
                    "node_id": self.node["id"],
                    "name": method,
                    "protocol": "shadowsocks",
                    "ss_method": method,
                    "port": reserved.getsockname()[1],
                }
                response = self.post("/inbounds", body)
                self.assertEqual(response.status_code, 201)
                self.endpoints.append(body | {"id": response.json()["id"]})
        self.user = self.post("/users", {"name": "ss-account"}).json()
        self.second = self.post(
            f"/users/{self.user['id']}/devices", {"name": "second"}
        ).json()
        self.token = (
            self.client.get(f"/api/users/{self.user['id']}/subscription")
            .json()["url"]
            .split("/sub/")[1]
            .split("?")[0]
        )

    def links(self):
        response = self.client.get("/sub/" + self.token + "?format=raw")
        self.assertEqual(response.status_code, 200)
        return response.text.splitlines()

    def proxies(self):
        response = self.client.get("/sub/" + self.token + "?format=clash")
        self.assertEqual(response.status_code, 200)
        return response.json()["proxies"]

    def user_change(self, **fields):
        response = self.client.put(
            "/api/users/" + self.user["id"],
            headers=self.headers,
            json={"name": self.user["name"], "quota": 0, "enabled": True, **fields},
        )
        self.assertEqual(response.status_code, 200)


class ShadowsocksAPITest(ShadowsocksFixture):
    def test_exports_key_separation_no_empty_2022_fallback_and_input_guards(self):
        links = self.links()
        self.assertEqual(len(links), 10)
        proxies = self.proxies()
        self.assertTrue(
            [decode_link(x) for x in links] == proxies,
            "URI and Mihomo exports disagree",
        )
        self.assertEqual(len({p["password"] for p in proxies}), 10)
        rows = self.client.get("/api/inbounds").json()
        self.assertTrue(all("ss_server_key" not in r["settings"] for r in rows))
        with database() as db:
            stored = list(db.execute("SELECT * FROM inbounds"))
            for row in stored:
                settings = json.loads(row["settings"])
                if settings["ss_method"].startswith("2022-"):
                    self.assertTrue(settings["ss_server_key"].startswith("fernet:"))
                    self.assertNotIn(
                        unseal(settings["ss_server_key"]), json.dumps(rows)
                    )
        for p in proxies:
            self.assertNotIn("tls", p)
            if p["cipher"].startswith("2022-"):
                for key in p["password"].split(":"):
                    self.assertEqual(
                        len(base64.b64decode(key)), 16 if "128" in p["cipher"] else 32
                    )
        intent = self.client.get(
            "/api/agent/config",
            headers={"Authorization": "Bearer " + self.node["token"]},
        ).json()
        with database() as db:
            payload = db.execute(
                "SELECT payload FROM deployments WHERE id=?", (intent["job_id"],)
            ).fetchone()[0]
            self.assertTrue(
                payload.startswith("fernet:"),
                "Queued config must not persist cleartext Shadowsocks keys",
            )
            self.assertTrue(
                json.loads(unseal(payload))["config"] == intent["config"],
                "Sealed job lost config",
            )
        self.assertEqual(compile_config(stored, [])["inbounds"][1:], [])
        base = self.endpoints[0]
        for changes in (
            {"ss_method": "none"},
            {"ss_method": "2022-blake3-chacha20-poly1305"},
            {"transport": "ws"},
            {"sni": "example.com"},
            {"cert_file": "/certificate"},
        ):
            self.assertEqual(self.post("/inbounds", base | changes).status_code, 422)
        self.assertNotEqual(
            device_key("secret", "i1", METHODS[0]),
            device_key("secret", "i2", METHODS[0]),
        )
        before = self.links()
        for body in self.endpoints:
            response = self.client.put(
                "/api/inbounds/" + body["id"], headers=self.headers, json=body
            )
            self.assertEqual(response.status_code, 200)
        self.assertTrue(
            before == self.links(), "Editing metadata rotated private credentials"
        )
        self.post("/devices/" + self.second["id"] + "/rotate-secret", {})
        after = self.links()
        self.assertEqual(sum(a != b for a, b in zip(before, after)), 5)
        self.login("operator")
        self.assertEqual(self.post("/inbounds", base).status_code, 403)


class _UDP(socketserver.BaseRequestHandler):
    def handle(self):
        value, sock = self.request
        sock.sendto(value, self.client_address)


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_XRAY"),
    "Set DONINO_TEST_XRAY for real Shadowsocks clients",
)
class RealShadowsocksTest(ShadowsocksFixture):
    def setUp(self):
        super().setUp()
        self.env = patch.dict(
            os.environ,
            DONINO_PANEL_URL="http://127.0.0.1:8000",
            DONINO_NODE_TOKEN=self.node["token"],
            DONINO_NODE_STATE=self.tmp.name + "/ss-node",
            DONINO_XRAY=os.path.abspath(os.environ["DONINO_TEST_XRAY"]),
        )
        self.env.start()
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), _UDP)
        for srv in (self.http, self.udp):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.agent = NodeAgent()
        self.agent.client.close()
        self.agent.client = _LocalPanel(self.client, self.node["token"])
        self.agent.tick()
        self.serial = 0

    def tearDown(self):
        try:
            self.agent.close()
            for srv in (self.http, self.udp):
                srv.shutdown()
                srv.server_close()
        finally:
            self.env.stop()
            super().tearDown()

    @contextlib.contextmanager
    def client_proxy(self, proxy):
        self.serial += 1
        socks = _free_port()
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": socks,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": proxy["server"],
                                "port": proxy["port"],
                                "method": proxy["cipher"],
                                "password": proxy["password"],
                            }
                        ]
                    },
                }
            ],
        }
        path = Path(self.tmp.name) / f"private-client-{self.serial}.json"
        path.touch(mode=0o600)
        path.write_text(json.dumps(config))
        log = path.with_suffix(".log")
        log.touch(mode=0o600)
        with log.open("w") as output:
            proc = subprocess.Popen(
                [self.agent.binary, "run", "-c", str(path)],
                stdout=output,
                stderr=output,
            )
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    self.fail("Real Shadowsocks client failed to start")
                try:
                    with socket.create_connection(("127.0.0.1", socks), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        self.fail("Client listener deadline")
                    time.sleep(0.03)
            self.client_log_path = log
            yield socks
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            self.client_log = log.read_text(errors="replace")
            path.unlink(missing_ok=True)

    def transfer(self, proxy, *, ok=True, udp=False):
        with self.client_proxy(proxy) as port:
            if udp:
                # A live SOCKS UDP association and RFC1928 UDP datagram. The
                # destination is the isolated loopback echo, never the Internet.
                with socket.create_connection(
                    ("127.0.0.1", port), timeout=3
                ) as control:
                    control.sendall(b"\x05\x01\x00")
                    self.assertEqual(control.recv(2), b"\x05\x00")
                    control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
                    reply = control.recv(32)
                    self.assertEqual(reply[:4], b"\x05\x00\x00\x01")
                    relay = (
                        socket.inet_ntoa(reply[4:8]),
                        int.from_bytes(reply[8:10], "big"),
                    )
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data:
                        data.settimeout(2)
                        packet = (
                            b"\x00\x00\x00\x01\x7f\x00\x00\x01"
                            + self.udp.server_address[1].to_bytes(2, "big")
                            + MARKER
                        )
                        data.sendto(packet, relay)
                        try:
                            body = data.recv(4096)
                        except OSError:
                            body = b""
            else:
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=2
                    ) as conn:
                        _socks_connect(conn, self.http.server_port)
                        conn.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        response = http.client.HTTPResponse(conn)
                        response.begin()
                        body = response.read(65536)
                except (OSError, http.client.HTTPException):
                    body = b""
            if ok:
                if MARKER not in body:
                    import re

                    diagnostic = self.client_log_path.read_text(errors="replace")[
                        -1500:
                    ]
                    print(re.sub(r"[A-Za-z0-9+/=_-]{32,}", "[redacted]", diagnostic))
                self.assertIn(MARKER, body, proxy["cipher"] + " transfer")
            else:
                self.assertNotIn(MARKER, body, proxy["cipher"] + " rejection")

    def test_real_profiles_udp_revocation_rotation_quota_period_and_expiry(self):
        proxies = [decode_link(x) for x in self.links()]
        primary = [p for p in proxies if " · second · " not in p["name"]]
        secondary = [p for p in proxies if " · second · " in p["name"]]
        for proxy in proxies:
            self.transfer(proxy)
            self.transfer(proxy, udp=True)
        self.agent.tick()
        before = self.client.get("/api/users/" + self.user["id"] + "/devices").json()
        self.assertTrue(all(d["uploaded"] > 0 and d["downloaded"] > 0 for d in before))
        used = self.client.get("/api/users").json()[0]["used"]
        self.agent.tick()
        self.assertEqual(self.client.get("/api/users").json()[0]["used"], used)
        # Server-key-only authentication must fail while 2022 multi-user mode is active.
        for p in primary:
            bad = copy.deepcopy(p)
            bad["password"] = (
                p["password"].split(":")[0]
                if p["cipher"].startswith("2022-")
                else "incorrect-password"
            )
            self.transfer(bad, ok=False)
        # Verify an already-open stream is actually terminated by device revoke.
        with self.client_proxy(secondary[-1]) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
                _socks_connect(stream, self.http.server_port)
                stream.sendall(b"GET /echo HTTP/1.0\r\nHost: localhost\r\n\r\n")
                header = b""
                while b"\r\n\r\n" not in header:
                    header += stream.recv(1)
                stream.sendall(b"ping")
                self.assertEqual(stream.recv(4), b"ping")
                self.client.put(
                    "/api/devices/" + self.second["id"],
                    headers=self.headers,
                    json={"name": "second", "enabled": False},
                )
                self.agent.tick()
                try:
                    stream.sendall(b"pong")
                    result = stream.recv(4)
                except OSError:
                    result = b""
                self.assertNotEqual(result, b"pong")
        for p in secondary:
            self.transfer(p, ok=False)
            self.transfer(p, ok=False, udp=True)
        for p in primary:
            self.transfer(p)
            self.transfer(p, udp=True)
        self.post("/users/" + self.user["id"] + "/rotate-credentials", {})
        with database() as db:
            self.token = db.execute(
                "SELECT token FROM users WHERE id=?", (self.user["id"],)
            ).fetchone()[0]
        self.agent.tick()
        for p in primary:
            self.transfer(p, ok=False)
        fresh = [decode_link(x) for x in self.links()]
        for p in fresh:
            self.transfer(p)
        self.agent.tick()
        self.user_change(quota=1)
        self.agent.tick()
        self.assertEqual(self.agent.config["inbounds"][1:], [])
        for p in fresh:
            self.transfer(p, ok=False)
        self.user_change(quota=10000000)
        self.post("/users/" + self.user["id"] + "/reset-traffic", {})
        self.agent.tick()
        for p in fresh:
            self.transfer(p)
        self.agent.tick()
        periods = self.client.get("/api/users/" + self.user["id"] + "/periods").json()
        self.assertGreaterEqual(len(periods), 2)
        self.assertGreater(periods[0]["uploaded"] + periods[0]["downloaded"], 0)
        expires = int(time.time()) + 5
        self.user_change(expires=expires)
        self.agent.tick()
        self.transfer(fresh[-1])
        time.sleep(max(0, expires - time.time() + 0.1))
        self.agent.tick()
        self.assertEqual(self.agent.config["inbounds"][1:], [])
        for p in fresh:
            self.transfer(p, ok=False)

    @unittest.skipUnless(
        os.environ.get("DONINO_TEST_MIHOMO"),
        "Set DONINO_TEST_MIHOMO for exported Mihomo profiles",
    )
    def test_real_mihomo_exports(self):
        from test_mihomo import _Mihomo

        processes = []
        client = _Mihomo(
            os.environ["DONINO_TEST_MIHOMO"], Path(self.tmp.name), processes
        )
        client.echo_port = self.http.server_port
        for proxy in self.proxies():
            body, _ = client.run(proxy)
            self.assertIn(MARKER, body, proxy["cipher"])
        self.agent.tick()
        devices = self.client.get("/api/users/" + self.user["id"] + "/devices").json()
        self.assertTrue(all(d["downloaded"] > 0 for d in devices))
