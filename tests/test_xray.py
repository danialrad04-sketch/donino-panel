"""Opt-in real protocol tests: DONINO_TEST_XRAY=/path/to/xray python -m unittest discover -s tests -v."""

import datetime
import copy
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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.db import database, hash_password
from agent.main import NodeAgent


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(p):
    for _ in range(60):
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Local Xray port did not open")


class Handler(BaseHTTPRequestHandler):
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
        body = b"donino-real-proxy-ok" * 500
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@unittest.skipUnless(
    os.environ.get("DONINO_TEST_XRAY"), "Set DONINO_TEST_XRAY for live Xray tests"
)
class XrayTest(unittest.TestCase):
    def test_protocols_agent_stats_and_revocation(self):
        binary = os.path.abspath(os.environ["DONINO_TEST_XRAY"])
        old = dict(os.environ)
        processes = []
        agent = None
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            os.environ.update(
                DONINO_DB=str(folder / "panel.db"),
                DONINO_DATABASE_URL="",
                DONINO_KEY_FILE=str(folder / "master.key"),
                DONINO_SECURE_COOKIE="false",
                DONINO_PANEL_URL="http://127.0.0.1:8000",
                DONINO_NODE_STATE=str(folder / "node"),
                DONINO_XRAY=binary,
            )
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            (folder / "cert.pem").write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            (folder / "key.pem").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=http.serve_forever, daemon=True)
            thread.start()
            try:
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
                            json={
                                "username": "admin",
                                "password": "test-password-long",
                            },
                        ).status_code,
                        200,
                    )
                    user = panel.post(
                        "/api/users", json={"name": "real-connection"}
                    ).json()
                    with database() as db:
                        credential = db.execute(
                            "SELECT credential FROM users WHERE id=?", (user["id"],)
                        ).fetchone()[0]
                    node = panel.post(
                        "/api/nodes", json={"name": "local-test", "host": "127.0.0.1"}
                    ).json()
                    os.environ["DONINO_NODE_TOKEN"] = node["token"]
                    tls_target = port()
                    reality_target = subprocess.Popen(
                        [
                            "openssl",
                            "s_server",
                            "-accept",
                            f"127.0.0.1:{tls_target}",
                            "-cert",
                            str(folder / "cert.pem"),
                            "-key",
                            str(folder / "key.pem"),
                            "-www",
                            "-tls1_3",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    processes.append(reality_target)
                    wait_port(tls_target)
                    for protocol in ["vless", "vmess", "trojan"]:
                        response = panel.post(
                            "/api/inbounds",
                            json={
                                "node_id": node["id"],
                                "name": protocol,
                                "protocol": protocol,
                                "port": port(),
                                "sni": "localhost",
                                "target": f"localhost:{tls_target}",
                                "cert_file": str(folder / "cert.pem"),
                                "key_file": str(folder / "key.pem"),
                            },
                        )
                        self.assertEqual(response.status_code, 201, response.text)
                    original = panel.get(
                        "/api/agent/config",
                        headers={"Authorization": "Bearer " + node["token"]},
                    ).json()
                    original_path = folder / "production-shape.json"
                    original_path.write_text(json.dumps(original["config"]))
                    checked = subprocess.run(
                        [binary, "run", "-test", "-c", str(original_path)],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        checked.returncode, 0, checked.stdout + checked.stderr
                    )
                    agent = NodeAgent()
                    agent.client.close()

                    # Real panel endpoints, with an explicit test-only route override for the local HTTP fixture.
                    class LocalPanel:
                        def post(self, path, **kwargs):
                            return panel.post(
                                path,
                                headers={"Authorization": "Bearer " + node["token"]},
                                **kwargs,
                            )

                        def get(self, path):
                            response = panel.get(
                                path,
                                headers={"Authorization": "Bearer " + node["token"]},
                            )
                            value = response.json()
                            value["config"]["routing"]["rules"] = value["config"][
                                "routing"
                            ]["rules"][:1]
                            import httpx

                            return httpx.Response(
                                200,
                                json=value,
                                request=httpx.Request("GET", "http://test" + path),
                            )

                    agent.client = LocalPanel()
                    agent.tick()
                    listed = panel.get("/api/inbounds").json()
                    socks_ports = {}
                    for inbound in listed:
                        protocol = inbound["protocol"]
                        socks = port()
                        socks_ports[protocol] = socks
                        s = inbound["settings"]
                        if protocol in ("vless", "vmess"):
                            usr = (
                                {"id": credential, "encryption": "none"}
                                if protocol == "vless"
                                else {"id": credential, "security": "auto"}
                            )
                            if protocol == "vless":
                                usr["flow"] = "xtls-rprx-vision"
                            settings = {
                                "vnext": [
                                    {
                                        "address": "127.0.0.1",
                                        "port": inbound["port"],
                                        "users": [usr],
                                    }
                                ]
                            }
                        else:
                            settings = {
                                "servers": [
                                    {
                                        "address": "127.0.0.1",
                                        "port": inbound["port"],
                                        "password": credential,
                                    }
                                ]
                            }
                        stream = {
                            "network": "ws" if protocol == "vmess" else "tcp",
                            "security": "reality" if protocol == "vless" else "tls",
                        }
                        if protocol == "vless":
                            stream["realitySettings"] = {
                                "serverName": "localhost",
                                "fingerprint": "chrome",
                                "password": s["public_key"],
                                "shortId": s["short_id"],
                            }
                        else:
                            stream["tlsSettings"] = {
                                "serverName": "localhost",
                                "pinnedPeerCertSha256": cert.fingerprint(
                                    hashes.SHA256()
                                ).hex(),
                            }  # Test certificate only.
                        if protocol == "vmess":
                            stream["wsSettings"] = {"path": s["path"]}
                        config = {
                            "log": {"loglevel": "warning"},
                            "inbounds": [
                                {
                                    "listen": "127.0.0.1",
                                    "port": socks,
                                    "protocol": "socks",
                                    "settings": {"auth": "noauth"},
                                }
                            ],
                            "outbounds": [
                                {
                                    "protocol": protocol,
                                    "settings": settings,
                                    "streamSettings": stream,
                                }
                            ],
                        }
                        path = folder / f"client-{protocol}.json"
                        path.write_text(json.dumps(config))
                        checked = subprocess.run(
                            [binary, "run", "-test", "-c", str(path)],
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(
                            checked.returncode, 0, checked.stdout + checked.stderr
                        )
                        client = subprocess.Popen(
                            [binary, "run", "-c", str(path)],
                            stdout=subprocess.DEVNULL,
                            stderr=None,
                        )
                        processes.append(client)
                        wait_port(socks)
                        with socket.create_connection(
                            ("127.0.0.1", socks), timeout=15
                        ) as sock:
                            sock.sendall(b"\x05\x01\x00")
                            self.assertEqual(sock.recv(2), b"\x05\x00")
                            sock.sendall(
                                b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                                + http.server_port.to_bytes(2, "big")
                            )
                            reply = sock.recv(10)
                            self.assertEqual(reply[1], 0, protocol)
                            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                            body = b""
                            while True:
                                chunk = sock.recv(16384)
                                if not chunk:
                                    break
                                body += chunk
                            self.assertIn(b"donino-real-proxy-ok", body, protocol)
                        print(f"  Real {protocol} transfer passed ({len(body)} bytes)")
                    # Keep a real encrypted stream open while adding another user to all three inbounds.
                    with socket.create_connection(
                        ("127.0.0.1", socks_ports["vmess"]), timeout=15
                    ) as stream:
                        stream.sendall(b"\x05\x01\x00")
                        self.assertEqual(stream.recv(2), b"\x05\x00")
                        stream.sendall(
                            b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                            + http.server_port.to_bytes(2, "big")
                        )
                        self.assertEqual(stream.recv(10)[1], 0)
                        stream.sendall(b"GET /echo HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        header = b""
                        while not header.endswith(b"\r\n\r\n"):
                            header += stream.recv(1)
                        stream.sendall(b"PING")
                        self.assertEqual(stream.recv(4), b"PING")
                        pid, epoch = agent.proc.pid, agent.epoch
                        second = panel.post(
                            "/api/users", json={"name": "live-added-user"}
                        ).json()
                        agent.tick()
                        self.assertEqual(agent.proc.pid, pid)
                        self.assertEqual(agent.epoch, epoch)
                        self.assertEqual(agent.apply_mode, "hot")
                        stream.sendall(b"PONG")
                        self.assertEqual(stream.recv(4), b"PONG")
                        # Verify actual Xray user managers on all three inbounds.
                        for inbound in listed:
                            result = subprocess.run(
                                [
                                    binary,
                                    "api",
                                    "inboundusercount",
                                    "-s=127.0.0.1:10085",
                                    "-tag=" + inbound["id"],
                                ],
                                capture_output=True,
                                text=True,
                                check=True,
                            )
                            self.assertEqual(json.loads(result.stdout)["count"], 2)
                    panel.delete("/api/users/" + second["id"])
                    agent.tick()
                    self.assertNotEqual(agent.proc.pid, pid)
                    self.assertEqual(agent.apply_mode, "restart")
                    print(
                        "  Live additions passed on all protocols; an existing encrypted stream remained intact"
                    )
                    agent.tick()
                    used = panel.get("/api/users").json()[0]["used"]
                    self.assertGreater(used, 20000)
                    agent.tick()
                    self.assertEqual(panel.get("/api/users").json()[0]["used"], used)
                    panel.put(
                        "/api/users/" + user["id"],
                        json={"name": user["name"], "quota": 1},
                    )
                    previous_pid = agent.proc.pid
                    agent.tick()
                    self.assertNotEqual(agent.proc.pid, previous_pid)
                    config = json.loads((folder / "node/config.json").read_text())
                    for inbound in config["inbounds"][1:]:
                        self.assertEqual(inbound["settings"]["clients"], [])
                    self.assertEqual(
                        panel.get("/api/users").json()[0]["status"], "limited"
                    )
                    print(
                        "  Real node accounting, duplicate-report handling, and quota removal passed"
                    )
                    previous_config = copy.deepcopy(agent.config)
                    previous_revision = agent.revision
                    bad = copy.deepcopy(previous_config)
                    bad["inbounds"][1]["port"] = (
                        http.server_port
                    )  # Binds in -test, fails when actually started.
                    with self.assertRaisesRegex(RuntimeError, "restored previous"):
                        agent.apply({"revision": "bad-startup", "config": bad})
                    self.assertTrue(agent.running())
                    self.assertEqual(agent.revision, previous_revision)
                    self.assertEqual(agent.apply_mode, "rollback")
                    self.assertEqual(
                        json.loads((folder / "node/config.json").read_text()),
                        previous_config,
                    )
                    print(
                        "  Real occupied-port startup failure restored the previous Xray config"
                    )
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


if __name__ == "__main__":
    unittest.main()
