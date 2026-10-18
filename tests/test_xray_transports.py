"""VLESS/VMess/Trojan over WebSocket and gRPC.

Unit checks run everywhere. The real-Xray test is opt-in:
    DONINO_TEST_XRAY=/path/to/xray python -m unittest discover -s tests -v

The real test starts the panel, a node agent and real Xray on both sides. Client
configs are built from the subscription URIs the panel publishes, so the links
are exercised as users receive them. TLS is verified against a test CA with
the correct hostname: verification is never disabled.
"""

import base64
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
from app.main import InboundInput, app
from app.db import database, hash_password

MARKER = b"donino-transport-ok"

# Inbounds exercised by the real test: (protocol, transport).
NEW_TRANSPORTS = [
    ("vless", "ws"),
    ("vless", "grpc"),
    ("vmess", "grpc"),
    ("trojan", "ws"),
]


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
        reality = _inbound("vless", "tcp", private_key="k", public_key="p", short_id="s")
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
        self.assertEqual(
            InboundInput(**base, protocol="vmess").transport, "ws"
        )
        self.assertEqual(
            InboundInput(**base, protocol="trojan").transport, "tcp"
        )
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


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_XRAY"), "Set DONINO_TEST_XRAY for live Xray tests"
)
class RealTransportTest(unittest.TestCase):
    def test_new_transports_carry_traffic_and_obey_cut_offs(self):
        binary = os.path.abspath(os.environ["DONINO_TEST_XRAY"])
        old = dict(os.environ)
        processes = []
        agent = None
        http = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                folder = Path(folder)
                os.environ.update(
                    DONINO_DB=str(folder / "panel.db"),
                    DONINO_SECURE_COOKIE="false",
                    DONINO_PANEL_URL="http://127.0.0.1:8000",
                    DONINO_NODE_STATE=str(folder / "node"),
                    DONINO_XRAY=binary,
                )
                ca_path, cert_path, key_path = _write_test_pki(folder)
                with TestClient(app) as panel:
                    with database() as db:
                        db.execute(
                            "INSERT INTO admins VALUES(?,?,?)",
                            ("admin", hash_password("test-password-long"), "owner"),
                        )
                    panel.headers["X-Donino"] = "1"
                    self.assertEqual(
                        panel.post(
                            "/api/login",
                            json={"username": "admin", "password": "test-password-long"},
                        ).status_code,
                        200,
                    )
                    user = panel.post(
                        "/api/users", json={"name": "transport-user"}
                    ).json()
                    uid = user["id"]
                    with database() as db:
                        token = db.execute(
                            "SELECT token FROM users WHERE id=?", (uid,)
                        ).fetchone()[0]
                    second = panel.post(
                        f"/api/users/{uid}/devices", json={"name": "second-phone"}
                    ).json()
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
                        self.assertEqual(response.status_code, 201, response.text)

                    agent = NodeAgent()
                    agent.client.close()
                    agent.client = _LocalPanel(panel, node["token"])
                    agent.tick()
                    checked = subprocess.run(
                        [binary, "run", "-test", "-c", str(folder / "node/config.json")],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

                    subscription = panel.get(f"/sub/{token}?format=raw").text
                    links = [line for line in subscription.splitlines() if line.strip()]
                    self.assertTrue(links, "subscription returned no links")

                    def link_for(protocol, transport, device):
                        for link in links:
                            if link.startswith("vmess://"):
                                value = json.loads(base64.b64decode(link[8:]))
                                label = value["ps"]
                                scheme_ok = protocol == "vmess" and value["net"] == transport
                            else:
                                scheme_ok = link.startswith(protocol + "://")
                                label = unquote(link.rsplit("#", 1)[1])
                                if scheme_ok:
                                    query = dict(parse_qsl(urlsplit(link).query))
                                    scheme_ok = query.get("type") == transport
                            if scheme_ok and f" · {protocol}-{transport} · {device} · " in label:
                                return link
                        raise AssertionError(f"no {protocol}/{transport} link for {device}")

                    def probe(protocol, transport, device, expect_ok=True, step=""):
                        link = link_for(protocol, transport, device)
                        config = _client_config(link, binary, folder, ca_path, _free_port())
                        client = _start_client(binary, config, folder, processes)
                        try:
                            body = _fetch(config["inbounds"][0]["port"], http.server_port)
                        except OSError:
                            body = b""
                        finally:
                            client.terminate()
                        if expect_ok:
                            self.assertIn(MARKER, body, f"{protocol}/{transport} {device} {step}")
                        else:
                            self.assertNotIn(MARKER, body, f"{protocol}/{transport} {device} {step}")
                        return len(body)

                    # 1. Default device and second device, every new transport.
                    default_device = _device_name(panel, uid, default=True)
                    for protocol, transport in NEW_TRANSPORTS:
                        self.assertGreater(
                            probe(protocol, transport, default_device, step="default"), 0
                        )
                        self.assertGreater(
                            probe(protocol, transport, "second-phone", step="second"), 0
                        )
                    agent.tick()
                    rows = {d["name"]: d for d in panel.get(f"/api/users/{uid}/devices").json()}
                    self.assertGreater(rows[default_device]["downloaded"], 0)
                    self.assertGreater(rows["second-phone"]["downloaded"], 0)
                    print("  Real VLESS/WS, VLESS/gRPC, VMess/gRPC and Trojan/WS transfers passed for two devices")

                    # 2. Negative control: a client that does not trust the test CA must fail.
                    link = link_for("vless", "ws", default_device)
                    untrusted = _client_config(link, binary, folder, None, _free_port())
                    client = _start_client(binary, untrusted, folder, processes)
                    try:
                        body = _fetch(untrusted["inbounds"][0]["port"], http.server_port)
                    except OSError:
                        body = b""
                    finally:
                        client.terminate()
                    self.assertNotIn(MARKER, body, "untrusted certificate was accepted")
                    print("  Certificate verification rejected a client without the test CA")

                    # 3. Device cut-off: the second device stops, the default keeps working.
                    panel.put(
                        f"/api/devices/{second['id']}",
                        json={"name": "second-phone", "enabled": False},
                    )
                    agent.tick()
                    for protocol, transport in NEW_TRANSPORTS:
                        probe(protocol, transport, "second-phone", expect_ok=False, step="device-off")
                        probe(protocol, transport, default_device, step="device-off-default")
                    print("  Disabled device was cut off on every new transport; the default device kept working")

                    # 4. User disabled: every device stops on the new transports.
                    panel.put(
                        f"/api/users/{uid}",
                        json={"name": user["name"], "enabled": False, "quota": 0},
                    )
                    agent.tick()
                    config = json.loads((folder / "node/config.json").read_text())
                    for inbound in config["inbounds"][1:]:
                        self.assertEqual(inbound["settings"]["clients"], [])
                    for protocol, transport in NEW_TRANSPORTS:
                        probe(protocol, transport, default_device, expect_ok=False, step="user-off")
                    print("  Disabled user was removed from every new inbound and its links stopped working")

                    # 5. Restore the user, then quota exhaustion, then period reset.
                    panel.put(
                        f"/api/users/{uid}",
                        json={"name": user["name"], "enabled": True, "quota": 0},
                    )
                    panel.put(
                        f"/api/devices/{second['id']}",
                        json={"name": "second-phone", "enabled": True},
                    )
                    agent.tick()
                    panel.put(
                        f"/api/users/{uid}",
                        json={"name": user["name"], "enabled": True, "quota": 1},
                    )
                    agent.tick()
                    config = json.loads((folder / "node/config.json").read_text())
                    for inbound in config["inbounds"][1:]:
                        self.assertEqual(inbound["settings"]["clients"], [])
                    self.assertEqual(panel.get("/api/users").json()[0]["status"], "limited")

                    panel.put(
                        f"/api/users/{uid}",
                        json={"name": user["name"], "enabled": True, "quota": 50_000_000},
                    )
                    panel.post(f"/api/users/{uid}/reset-traffic")
                    epoch, pid = agent.epoch, agent.proc.pid
                    agent.tick()
                    self.assertNotEqual(agent.epoch, epoch)
                    self.assertNotEqual(agent.proc.pid, pid)
                    for protocol, transport in NEW_TRANSPORTS:
                        self.assertGreater(
                            probe(protocol, transport, default_device, step="after-reset"), 0
                        )
                    print("  Quota exhaustion cut off all new transports; period reset restored them")

                    agent.close()
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


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
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


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _device_name(panel, uid, default):
    for row in panel.get(f"/api/users/{uid}/devices").json():
        if bool(row["is_default"]) == default:
            return row["name"]
    raise AssertionError("device not found")


def _write_test_pki(folder):
    """A test CA and a leaf certificate for localhost, signed by that CA."""
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


def _client_config(link, binary, folder, ca_path, socks_port):
    """Build an Xray client outbound from a subscription URI or VMess JSON."""
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
    if protocol == "vmess":
        settings = {
            "vnext": [
                {"address": host, "port": port, "users": [{"id": secret, "security": "auto"}]}
            ]
        }
    elif protocol == "vless":
        settings = {
            "vnext": [
                {"address": host, "port": port, "users": [{"id": secret, "encryption": "none"}]}
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
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": protocol, "settings": settings, "streamSettings": stream}],
    }


def _start_client(binary, config, folder, processes):
    path = folder / f"client-{time.monotonic_ns()}.json"
    path.write_text(json.dumps(config))
    checked = subprocess.run(
        [binary, "run", "-test", "-c", str(path)], capture_output=True, text=True
    )
    if checked.returncode != 0:
        raise AssertionError(checked.stdout + checked.stderr)
    proc = subprocess.Popen(
        [binary, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    processes.append(proc)
    for _ in range(60):
        try:
            with socket.create_connection(
                ("127.0.0.1", config["inbounds"][0]["port"]), timeout=0.1
            ):
                return proc
        except OSError:
            time.sleep(0.1)
    raise AssertionError("client SOCKS port did not open")


def _fetch(socks_port, target_port, timeout=15):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as sock:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise OSError("SOCKS auth refused")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            raise OSError("SOCKS connect refused")
        sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        body = b""
        while chunk := sock.recv(65536):
            body += chunk
        return body


if __name__ == "__main__":
    unittest.main()
