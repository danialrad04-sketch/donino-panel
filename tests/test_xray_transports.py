"""VLESS/VMess/Trojan over WebSocket and gRPC: acceptance with real Xray.

Unit checks run everywhere. The real-Xray checks are opt-in:
    DONINO_TEST_XRAY=/path/to/xray python -m unittest discover -s tests -v

Every real check starts the panel, one node agent and real Xray on both sides.
Client configs are built from the subscription URIs the panel publishes, so the
links are exercised as users receive them. TLS is verified against a test CA
with the correct hostname. Verification is never disabled and allowInsecure is
never used. Expiry is real wall-clock expiry; the clock is not mocked.
"""

import base64
import contextlib
import datetime
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent.main import NodeAgent
from app.core import compile_config, profiles
from app.db import database, hash_password
from app.main import InboundInput, app
from support import configure

MARKER = b"donino-transport-ok"

# Inbounds exercised by the real checks: (protocol, transport).
NEW_TRANSPORTS = [
    ("vless", "ws"),
    ("vless", "grpc"),
    ("vmess", "grpc"),
    ("trojan", "ws"),
]
DEFAULT_CA = object()  # sentinel: trust the lab's CA


def _inbound(protocol, transport, **settings):
    base = {
        "sni": "localhost",
        "target": "www.microsoft.com:443",
        "path": "/donino",
        "service_name": "donino",
        "cert_file": "/etc/donino/tls/fullchain.pem",
        "key_file": "/etc/donino/tls/privkey.pem",
        "transport": transport,
    }
    base.update(settings)
    return {
        "id": f"id-{protocol}-{transport}",
        "node_id": "node",
        "node_name": "edge",
        "name": f"{protocol}-{transport}",
        "protocol": protocol,
        "port": 443,
        "host": "203.0.113.10",
        "enabled": True,
        "node_enabled": True,
        "settings": json.dumps(base),
    }


class TransportUnitTest(unittest.TestCase):
    def test_vision_flow_is_reality_tcp_only(self):
        reality = _inbound(
            "vless", "tcp", private_key="k", public_key="p", short_id="s"
        )
        ws = _inbound("vless", "ws")
        grpc = _inbound("vless", "grpc")
        config = compile_config(
            [reality, ws, grpc],
            [{"id": "d", "secret": "uuid-1", "eligible": True}],
        )
        by_tag = {i["tag"]: i for i in config["inbounds"][1:]}
        self.assertEqual(
            by_tag[reality["id"]]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision",
        )
        self.assertNotIn("flow", by_tag[ws["id"]]["settings"]["clients"][0])
        self.assertNotIn("flow", by_tag[grpc["id"]]["settings"]["clients"][0])
        self.assertEqual(by_tag[ws["id"]]["streamSettings"]["network"], "ws")
        self.assertEqual(
            by_tag[ws["id"]]["streamSettings"]["wsSettings"], {"path": "/donino"}
        )
        grpc_stream = by_tag[grpc["id"]]["streamSettings"]
        self.assertEqual(grpc_stream["network"], "grpc")
        self.assertEqual(grpc_stream["grpcSettings"], {"serviceName": "donino"})
        self.assertEqual(grpc_stream["tlsSettings"]["alpn"], ["h2"])

    def test_legacy_rows_without_transport_keep_their_transport(self):
        # Rows created before the transport key existed have no "transport" in settings.
        legacy = {
            "sni": "localhost",
            "path": "/donino",
            "cert_file": "/c",
            "key_file": "/k",
        }
        legacy_vmess = _inbound("vmess", "ws")
        legacy_vmess["settings"] = json.dumps(legacy)
        legacy_trojan = _inbound("trojan", "tcp")
        legacy_trojan["settings"] = json.dumps(legacy)
        config = compile_config(
            [legacy_vmess, legacy_trojan],
            [{"id": "d", "secret": "s", "eligible": True}],
        )
        vmess_stream = config["inbounds"][1]["streamSettings"]
        trojan_stream = config["inbounds"][2]["streamSettings"]
        self.assertEqual(vmess_stream["network"], "ws")
        self.assertEqual(trojan_stream["network"], "tcp")
        self.assertEqual(trojan_stream["security"], "tls")

    def test_profiles_emit_uri_and_mihomo_for_every_new_transport(self):
        clients = [
            {
                "id": "d",
                "secret": "secret-1",
                "device_name": "phone",
                "eligible": True,
            }
        ]
        inbounds = [
            _inbound("vless", "ws"),
            _inbound("vless", "grpc"),
            _inbound("vmess", "grpc"),
            _inbound("trojan", "ws"),
        ]
        links, clash = profiles(clients, inbounds)
        self.assertEqual(len(links), 4)
        self.assertEqual(len(clash["proxies"]), 4)

        by_scheme = {}
        for link in links:
            by_scheme.setdefault(link.split("://", 1)[0], []).append(link)

        vless_ws, vless_grpc = by_scheme["vless"]
        query = dict(parse_qsl(urlsplit(vless_ws).query))
        self.assertEqual(query["type"], "ws")
        self.assertEqual(query["security"], "tls")
        self.assertEqual(query["path"], "/donino")
        self.assertNotIn("flow", query)
        self.assertEqual(
            dict(parse_qsl(urlsplit(vless_grpc).query))["serviceName"], "donino"
        )

        trojan = dict(parse_qsl(urlsplit(by_scheme["trojan"][0]).query))
        self.assertEqual(trojan["type"], "ws")
        self.assertEqual(trojan["path"], "/donino")

        vmess = json.loads(base64.b64decode(by_scheme["vmess"][0][8:]))
        self.assertEqual(vmess["net"], "grpc")
        self.assertEqual(vmess["type"], "gun")
        self.assertEqual(vmess["path"], "donino")

        proxies = {p["name"].split(" · ")[1]: p for p in clash["proxies"]}
        self.assertEqual(proxies["vless-ws"]["network"], "ws")
        self.assertEqual(proxies["vless-ws"]["ws-opts"]["path"], "/donino")
        self.assertNotIn("flow", proxies["vless-ws"])
        self.assertEqual(
            proxies["vless-grpc"]["grpc-opts"], {"grpc-service-name": "donino"}
        )
        self.assertEqual(proxies["vmess-grpc"]["network"], "grpc")
        self.assertEqual(proxies["trojan-ws"]["network"], "ws")
        self.assertEqual(proxies["trojan-ws"]["password"], "secret-1")

    def test_api_accepts_only_supported_protocol_transport_pairs(self):
        base = {
            "node_id": "node",
            "name": "x",
            "port": 443,
            "sni": "example.com",
            "cert_file": "/etc/donino/tls/fullchain.pem",
            "key_file": "/etc/donino/tls/privkey.pem",
        }
        for protocol, transport in NEW_TRANSPORTS:
            model = InboundInput(**base, protocol=protocol, transport=transport)
            self.assertEqual(model.transport, transport)
        self.assertEqual(InboundInput(**base, protocol="vmess").transport, "ws")
        self.assertEqual(InboundInput(**base, protocol="trojan").transport, "tcp")
        self.assertEqual(
            InboundInput(**base, protocol="vless", transport="tcp").transport, "tcp"
        )
        for protocol, transport in [
            ("vmess", "tcp"),
            ("trojan", "grpc"),
            ("vless", "http"),
        ]:
            with self.assertRaises(ValidationError, msg=f"{protocol}/{transport}"):
                InboundInput(**base, protocol=protocol, transport=transport)

    def test_tls_transports_require_certificate_paths(self):
        with self.assertRaises(ValidationError):
            InboundInput(
                node_id="node",
                name="x",
                port=443,
                sni="example.com",
                protocol="vless",
                transport="grpc",
            )
        # REALITY over TCP does not need a certificate on the node.
        InboundInput(
            node_id="node", name="x", port=443, sni="example.com", protocol="vless"
        )


# ---------------------------------------------------------------- real Xray


class _EchoHandler(BaseHTTPRequestHandler):
    """/echo streams bytes back; every other path returns a fixed marker body."""

    def do_GET(self):
        if self.path == "/echo":
            self.send_response(200)
            self.end_headers()
            try:
                while value := self.rfile.read(4):
                    self.wfile.write(value)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        body = MARKER * 500
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class _LocalPanel:
    """Node-side fetches go through the real panel API; only the test routing rule is trimmed."""

    def __init__(self, panel, token):
        self.panel = panel
        self.token = token

    def post(self, path, **kwargs):
        return self.panel.post(
            path, headers={"Authorization": "Bearer " + self.token}, **kwargs
        )

    def get(self, path, **kwargs):
        import httpx

        response = self.panel.get(
            path, headers={"Authorization": "Bearer " + self.token}, **kwargs
        )
        value = response.json()
        # The local echo target is 127.0.0.1, which the production geoip:private rule blocks.
        value["config"]["routing"]["rules"] = value["config"]["routing"]["rules"][:1]
        return httpx.Response(
            200, json=value, request=httpx.Request("GET", "http://test" + path)
        )

    def close(self):
        pass


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_test_pki(folder):
    """A test CA and a leaf certificate for localhost, signed by that CA."""
    folder.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    def name(common):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    def builder(subject, issuer, key):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
        )

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = name("Donino transport test CA")
    ca_cert = (
        builder(ca_name, ca_name, ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        builder(name("localhost"), ca_cert.subject, leaf_key)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = folder / "ca.pem"
    cert_path = folder / "server.pem"
    key_path = folder / "server.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def _client_config(link, socks_port, ca_path, server_name=None, loglevel="warning"):
    """Xray client outbound built from a subscription URI or VMess JSON.

    server_name overrides the SNI and WebSocket Host for negative controls only.
    """
    if link.startswith("vmess://"):
        value = json.loads(base64.b64decode(link[8:]))
        protocol = "vmess"
        secret = value["id"]
        host, port = value["add"], int(value["port"])
        network, sni = value["net"], value["sni"]
        path = value["path"]
        service = value["path"]
    else:
        url = urlsplit(link)
        protocol = url.scheme
        secret = url.username
        host, port = url.hostname, url.port
        query = dict(parse_qsl(url.query))
        network, sni = query["type"], query["sni"]
        path = query.get("path", "")
        service = query.get("serviceName", "")
    sni = server_name or sni
    if protocol == "vmess":
        settings = {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [{"id": secret, "security": "auto"}],
                }
            ]
        }
    elif protocol == "vless":
        settings = {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [{"id": secret, "encryption": "none"}],
                }
            ]
        }
    else:
        settings = {"servers": [{"address": host, "port": port, "password": secret}]}
    tls = {"serverName": sni, "disableSystemRoot": True}
    if ca_path is not None:
        tls["certificates"] = [{"usage": "verify", "certificateFile": str(ca_path)}]
    if network == "grpc":
        tls["alpn"] = ["h2"]
    stream = {"network": network, "security": "tls", "tlsSettings": tls}
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": sni}}
    if network == "grpc":
        stream["grpcSettings"] = {"serviceName": service}
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [
            {"protocol": protocol, "settings": settings, "streamSettings": stream}
        ],
    }


def _recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("Connection closed before the expected reply")
        data.extend(chunk)
    return bytes(data)


def _socks_connect(sock, target_port):
    sock.sendall(b"\x05\x01\x00")
    if _recv_exact(sock, 2) != b"\x05\x00":
        raise OSError("SOCKS auth refused")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
    reply = _recv_exact(sock, 4)
    if reply[:2] != b"\x05\x00":
        raise OSError("SOCKS connect refused")
    if reply[3] == 1:
        size = 4
    elif reply[3] == 4:
        size = 16
    elif reply[3] == 3:
        size = _recv_exact(sock, 1)[0]
    else:
        raise OSError("Invalid SOCKS reply address type")
    _recv_exact(sock, size + 2)


class Lab:
    """One panel, one node with the four new inbounds, and a node agent with real Xray."""

    def __init__(self, binary, folder, panel, agent, http, ca_path, processes):
        self.binary = binary
        self.folder = folder
        self.panel = panel
        self.agent = agent
        self.http = http
        self.ca_path = ca_path
        self.processes = processes
        self.clients = 0
        self.last_log = None

    # panel helpers
    def new_user(self, name, **fields):
        return self.panel.post("/api/users", json={"name": name, **fields}).json()

    def token(self, uid):
        with database() as db:
            return db.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()[
                0
            ]

    def devices(self, uid):
        return self.panel.get(f"/api/users/{uid}/devices").json()

    def default_device(self, uid):
        return next(row["name"] for row in self.devices(uid) if row["is_default"])

    def add_device(self, uid, name):
        return self.panel.post(f"/api/users/{uid}/devices", json={"name": name}).json()

    def set_device(self, device, name, enabled):
        return self.panel.put(
            f"/api/devices/{device['id']}", json={"name": name, "enabled": enabled}
        )

    def set_user(self, user, **fields):
        body = {"name": user["name"], "enabled": True, "quota": 0, **fields}
        return self.panel.put(f"/api/users/{user['id']}", json=body)

    def subscription(self, token, fmt="raw"):
        return self.panel.get(f"/sub/{token}?format={fmt}")

    def links(self, token):
        response = self.subscription(token)
        if response.status_code != 200:
            raise AssertionError(f"subscription returned {response.status_code}")
        return [line for line in response.text.splitlines() if line.strip()]

    @staticmethod
    def find(links, protocol, transport, device):
        for link in links:
            if link.startswith("vmess://"):
                value = json.loads(base64.b64decode(link[8:]))
                label = value["ps"]
                matches = protocol == "vmess" and value["net"] == transport
            else:
                matches = link.startswith(protocol + "://")
                label = unquote(link.rsplit("#", 1)[1])
                if matches:
                    matches = (
                        dict(parse_qsl(urlsplit(link).query)).get("type") == transport
                    )
            if matches and f" · {protocol}-{transport} · {device} · " in label:
                return link
        raise AssertionError(f"no {protocol}/{transport} link for device {device}")

    # node helpers
    def tick(self):
        self.agent.tick()

    def node_config(self):
        return json.loads((self.folder / "node/config.json").read_text())

    # traffic
    def fetch(self, link, ca=DEFAULT_CA, server_name=None, loglevel="warning"):
        """Start a real client from the link, fetch through it, stop it. Returns the body or b''."""
        self.clients += 1
        socks = _free_port()
        ca_path = self.ca_path if ca is DEFAULT_CA else ca
        config = _client_config(link, socks, ca_path, server_name, loglevel)
        path = self.folder / f"client-{self.clients}.json"
        path.write_text(json.dumps(config))
        log = self.folder / f"client-{self.clients}.log"
        checked = subprocess.run(
            [self.binary, "run", "-test", "-c", str(path)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if checked.returncode != 0:
            raise AssertionError(checked.stdout + checked.stderr)
        with open(log, "w") as handle:
            proc = subprocess.Popen(
                [self.binary, "run", "-c", str(path)],
                stdout=handle,
                stderr=subprocess.STDOUT,
            )
        self.processes.append(proc)
        try:
            for _ in range(60):
                try:
                    with socket.create_connection(("127.0.0.1", socks), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            try:
                with socket.create_connection(("127.0.0.1", socks), timeout=15) as sock:
                    _socks_connect(sock, self.http.server_port)
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    body = b""
                    while chunk := sock.recv(65536):
                        body += chunk
            except OSError:
                body = b""
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.last_log = log.read_text()
        return body

    def expect(self, link, ok, step, ca=DEFAULT_CA, server_name=None):
        body = self.fetch(link, ca=ca, server_name=server_name)
        label = f"{link.split('://', 1)[0]} {step}"
        if ok:
            self.assertIn(MARKER, body, label)
        else:
            self.assertNotIn(MARKER, body, label)
        return len(body)

    def assertIn(self, needle, haystack, label):
        if needle not in haystack:
            raise AssertionError(f"{label}: expected transfer to succeed")

    def assertNotIn(self, needle, haystack, label):
        if needle in haystack:
            raise AssertionError(f"{label}: transfer should have been refused")


@contextlib.contextmanager
def _lab(binary, folder):
    old = dict(os.environ)
    http = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    processes = []
    agent = None
    try:
        # Isolated database: SQLite file by default, or a disposable PostgreSQL schema.
        configure(folder)
        os.environ.update(
            DONINO_SECURE_COOKIE="false",
            DONINO_PANEL_URL="http://127.0.0.1:8000",
            DONINO_NODE_STATE=str(folder / "node"),
            DONINO_XRAY=binary,
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
            for protocol, transport in NEW_TRANSPORTS:
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
                        "service_name": f"svc-{protocol}",
                        "cert_file": str(cert_path),
                        "key_file": str(key_path),
                    },
                )
                if response.status_code != 201:
                    raise AssertionError(response.text)
            agent = NodeAgent()
            agent.client.close()
            agent.client = _LocalPanel(panel, node["token"])
            lab = Lab(binary, folder, panel, agent, http, ca_path, processes)
            agent.tick()
            checked = subprocess.run(
                [binary, "run", "-test", "-c", str(folder / "node/config.json")],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if checked.returncode != 0:
                raise AssertionError(checked.stdout + checked.stderr)
            yield lab
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


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_XRAY"), "Set DONINO_TEST_XRAY for live Xray tests"
)
class RealTransportTest(unittest.TestCase):
    def setUp(self):
        self.binary = os.path.abspath(os.environ["DONINO_TEST_XRAY"])
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_device_user_quota_and_period_cut_offs(self):
        """Per-device accounting, device and user cut-off, quota exhaustion and period reset."""
        with _lab(self.binary, self.folder) as lab:
            user = lab.new_user("transport-user")
            second = lab.add_device(user["id"], "second-phone")
            lab.tick()
            token = lab.token(user["id"])
            links = lab.links(token)
            default = lab.default_device(user["id"])

            for protocol, transport in NEW_TRANSPORTS:
                self.assertGreater(
                    lab.expect(
                        lab.find(links, protocol, transport, default), True, "default"
                    ),
                    0,
                )
                self.assertGreater(
                    lab.expect(
                        lab.find(links, protocol, transport, "second-phone"),
                        True,
                        "second",
                    ),
                    0,
                )
            lab.tick()
            rows = {d["name"]: d for d in lab.devices(user["id"])}
            self.assertGreater(rows[default]["downloaded"], 0)
            self.assertGreater(rows["second-phone"]["downloaded"], 0)
            print(
                "  Transfers passed on all four transports for two devices; device counters increased"
            )

            # Untrusted certificate: a client without the test CA must be refused.
            link = lab.find(links, "vless", "ws", default)
            untrusted = lab.fetch(link, ca=None)
            self.assertNotIn(MARKER, untrusted)

            lab.set_device(second, "second-phone", enabled=False)
            lab.tick()
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, "second-phone"),
                    False,
                    "device-off",
                )
                lab.expect(
                    lab.find(links, protocol, transport, default),
                    True,
                    "device-off-default",
                )
            print(
                "  Disabled device was cut off on every transport; the default device kept working"
            )

            lab.set_user(user, enabled=False)
            lab.tick()
            for inbound in lab.node_config()["inbounds"][1:]:
                self.assertEqual(inbound["settings"]["clients"], [])
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), False, "user-off"
                )
            print(
                "  Disabled user was removed from every new inbound and its links stopped working"
            )

            lab.set_user(user, enabled=True, quota=1)
            lab.tick()
            for inbound in lab.node_config()["inbounds"][1:]:
                self.assertEqual(inbound["settings"]["clients"], [])
            self.assertEqual(lab.panel.get("/api/users").json()[0]["status"], "limited")

            lab.set_user(user, enabled=True, quota=50_000_000)
            lab.panel.post(f"/api/users/{user['id']}/reset-traffic")
            epoch, pid = lab.agent.epoch, lab.agent.proc.pid
            lab.tick()
            self.assertNotEqual(lab.agent.epoch, epoch)
            self.assertNotEqual(lab.agent.proc.pid, pid)
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), True, "after-reset"
                )
            print(
                "  Quota exhaustion cut off all new transports; period reset restored them"
            )

    def test_live_add_is_hot_and_keeps_an_open_stream(self):
        with _lab(self.binary, self.folder) as lab:
            owner = lab.new_user("live-owner")
            lab.tick()
            owner_links = lab.links(lab.token(owner["id"]))
            owner_default = lab.default_device(owner["id"])

            # Open a long-lived stream through VLESS/WS before the change.
            link = lab.find(owner_links, "vless", "ws", owner_default)
            stream_socks = _free_port()
            config = _client_config(link, stream_socks, lab.ca_path)
            path = self.folder / "stream-client.json"
            path.write_text(json.dumps(config))
            proc = subprocess.Popen(
                [self.binary, "run", "-c", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            lab.processes.append(proc)
            stream = None
            try:
                for _ in range(60):
                    try:
                        socket.create_connection(
                            ("127.0.0.1", stream_socks), timeout=0.1
                        ).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                stream = socket.create_connection(
                    ("127.0.0.1", stream_socks), timeout=15
                )
                _socks_connect(stream, lab.http.server_port)
                stream.sendall(b"GET /echo HTTP/1.0\r\nHost: localhost\r\n\r\n")
                header = b""
                deadline = time.monotonic() + 15
                while not header.endswith(b"\r\n\r\n"):
                    if len(header) >= 16384 or time.monotonic() > deadline:
                        raise OSError("Echo response headers exceeded the test limit")
                    header += _recv_exact(stream, 1)
                stream.sendall(b"PING")
                self.assertEqual(_recv_exact(stream, 4), b"PING")

                pid, epoch = lab.agent.proc.pid, lab.agent.epoch
                newcomer = lab.new_user("live-newcomer")
                newdevice = lab.add_device(owner["id"], "live-device")
                lab.tick()
                self.assertEqual(lab.agent.proc.pid, pid, "live add restarted Xray")
                self.assertEqual(lab.agent.epoch, epoch, "live add changed the epoch")
                self.assertEqual(lab.agent.apply_mode, "hot")

                stream.sendall(b"PONG")
                self.assertEqual(_recv_exact(stream, 4), b"PONG")
                print(
                    "  Live add applied hot: Xray PID and epoch unchanged; open stream intact"
                )

                newcomer_links = lab.links(lab.token(newcomer["id"]))
                owner_links = lab.links(lab.token(owner["id"]))
                newcomer_default = lab.default_device(newcomer["id"])
                for protocol, transport in NEW_TRANSPORTS:
                    lab.expect(
                        lab.find(newcomer_links, protocol, transport, newcomer_default),
                        True,
                        "newcomer",
                    )
                    lab.expect(
                        lab.find(owner_links, protocol, transport, "live-device"),
                        True,
                        "new-device",
                    )
                lab.tick()

                counters = {d["name"]: d for d in lab.devices(newcomer["id"])}
                self.assertGreater(
                    counters[newcomer_default]["uploaded"]
                    + counters[newcomer_default]["downloaded"],
                    0,
                )
                device_rows = {d["id"]: d for d in lab.devices(owner["id"])}
                self.assertGreater(
                    device_rows[newdevice["id"]]["uploaded"]
                    + device_rows[newdevice["id"]]["downloaded"],
                    0,
                    "new device bytes were not attributed to its device id",
                )
                periods = lab.panel.get(f"/api/users/{newcomer['id']}/periods").json()
                total = sum(p["uploaded"] + p["downloaded"] for p in periods)
                self.assertGreater(total, 0, "newcomer period did not accumulate bytes")
                print(
                    "  Live-added user and device bytes reached their device ids and the current period"
                )
            finally:
                if stream is not None:
                    stream.close()

    def test_real_expiry_stops_stored_and_new_links(self):
        with _lab(self.binary, self.folder) as lab:
            expires = int(time.time()) + 30
            user = lab.new_user("expiring-user", expires=expires)
            lab.tick()
            links = lab.links(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), True, "before-expiry"
                )
            print(
                "  Transfers passed on all four transports before the real expiry time"
            )

            pid = lab.agent.proc.pid
            time.sleep(max(0.0, expires + 1 - time.time()))
            lab.tick()
            self.assertEqual(lab.agent.apply_mode, "restart")
            self.assertNotEqual(
                lab.agent.proc.pid, pid, "expiry removal should restart Xray"
            )
            for inbound in lab.node_config()["inbounds"][1:]:
                self.assertEqual(inbound["settings"]["clients"], [])
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), False, "after-expiry"
                )
            self.assertEqual(lab.subscription(lab.token(user["id"])).status_code, 404)
            self.assertEqual(
                lab.subscription(lab.token(user["id"]), "clash").status_code, 404
            )
            print(
                "  Real expiry removed the credential from Xray; stored links and new subscriptions stopped"
            )

    def test_expiry_set_to_past_via_api_revokes_on_tick(self):
        with _lab(self.binary, self.folder) as lab:
            user = lab.new_user("api-expiry-user", expires=int(time.time()) + 3600)
            lab.tick()
            links = lab.links(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), True, "before-change"
                )

            lab.set_user(user, expires=int(time.time()) - 60)
            lab.tick()
            self.assertEqual(lab.agent.apply_mode, "restart")
            for protocol, transport in NEW_TRANSPORTS:
                lab.expect(
                    lab.find(links, protocol, transport, default), False, "after-change"
                )
            self.assertEqual(lab.subscription(lab.token(user["id"])).status_code, 404)
            print(
                "  Expiry moved to the past through the API revoked the user on the next tick"
            )

    def test_tls_controls_for_each_transport(self):
        """Valid CA and correct hostname succeed; wrong CA and wrong hostname are refused."""
        with _lab(self.binary, self.folder) as lab:
            user = lab.new_user("tls-user")
            lab.tick()
            links = lab.links(lab.token(user["id"]))
            default = lab.default_device(user["id"])
            other_ca, _, _ = _write_test_pki(self.folder / "other-pki")
            for protocol, transport in NEW_TRANSPORTS:
                link = lab.find(links, protocol, transport, default)
                lab.expect(link, True, "valid-ca-and-hostname")
                wrong_ca = lab.fetch(link, ca=other_ca, loglevel="info")
                self.assertNotIn(
                    MARKER, wrong_ca, f"{protocol}/{transport} accepted an untrusted CA"
                )
                self.assertIn(
                    "certificate",
                    lab.last_log.lower(),
                    f"{protocol}/{transport}: TLS error not logged",
                )
                if protocol == "vless" and transport == "ws":
                    line = next(
                        l
                        for l in lab.last_log.splitlines()
                        if "certificate" in l.lower()
                    )
                    print("  Client log (wrong CA):", line.strip()[:200])
                wrong_host = lab.fetch(
                    link, server_name="wrong.example", loglevel="info"
                )
                self.assertNotIn(
                    MARKER,
                    wrong_host,
                    f"{protocol}/{transport} accepted a wrong hostname",
                )
                self.assertIn(
                    "certificate",
                    lab.last_log.lower(),
                    f"{protocol}/{transport}: hostname error not logged",
                )
            print(
                "  TLS: valid CA with localhost succeeded on all four; wrong CA and wrong hostname were refused"
            )


if __name__ == "__main__":
    unittest.main()
