"""Real OpenVPN 2.6 UDP/TCP clients, isolated namespaces and routed NAT.

Run only in the dedicated disposable privileged fixture container. No host
network, user VPS, public-domain or kernel-OpenVPN claim is inferred.
"""

import os
import logging
import json
import re
import subprocess
import stat
import sys
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.db import database, hash_password
from app.main import app
from app.node_identity import public_material
from agent.wireguard import command, OperationError
from agent.openvpn import OpenVPNAgent

BODY = b"donino-real-openvpn-transfer-" * 4096


def run():
    logger = logging.getLogger("donino-openvpn")
    logger.setLevel(logging.WARNING)
    logger.addHandler(logging.StreamHandler())
    if not Path("/dev/net/tun").exists():
        Path("/dev/net").mkdir(exist_ok=True)
        os.mknod("/dev/net/tun", stat.S_IFCHR | 0o600, os.makedev(10, 200))
    processes = []
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        os.environ.update(
            DONINO_DB=str(root / "panel.db"),
            DONINO_KEY_FILE=str(root / "master.key"),
            DONINO_PKI_DIR=str(root / "pki"),
            DONINO_PANEL_URL="https://panel.example",
            DONINO_OVPN_STATE=str(root / "node"),
            DONINO_SECURE_COOKIE="false",
        )
        (root / "origin").mkdir()
        (root / "origin/data").write_bytes(BODY)
        (root / "origin/large").write_bytes(b"x" * (64 * 1024 * 1024))
        # Namespace operations are restricted to this disposable container.
        for index, namespace in enumerate(("clienta", "clientb", "origin")):
            command(["ip", "netns", "add", namespace])
            host, peer = f"lab{index}", f"net{index}"
            command(["ip", "link", "add", host, "type", "veth", "peer", "name", peer])
            command(["ip", "link", "set", peer, "netns", namespace])
            subnet = f"10.200.{index}" if namespace != "origin" else "198.18.0"
            command(["ip", "address", "add", subnet + ".1/30", "dev", host])
            command(["ip", "link", "set", host, "up"])
            command(
                ["ip", "-n", namespace, "address", "add", subnet + ".2/30", "dev", peer]
            )
            command(["ip", "-n", namespace, "link", "set", peer, "up"])
            command(["ip", "-n", namespace, "link", "set", "lo", "up"])
            if os.environ.get("DONINO_TEST_OVPN_SPLIT") != "1":
                prefix = f"fd42:200:{index}"
                command(
                    [
                        "ip",
                        "-6",
                        "address",
                        "add",
                        prefix + "::1/64",
                        "dev",
                        host,
                        "nodad",
                    ]
                )
                command(
                    [
                        "ip",
                        "-n",
                        namespace,
                        "-6",
                        "address",
                        "add",
                        prefix + "::2/64",
                        "dev",
                        peer,
                        "nodad",
                    ]
                )
                command(
                    [
                        "ip",
                        "-n",
                        namespace,
                        "-6",
                        "route",
                        "add",
                        "default",
                        "via",
                        prefix + "::1",
                    ]
                )
                # Deterministic fixture neighbours avoid multicast/MLD startup
                # timing. These are only the owned namespace veth pairs.
                host_mac = json.loads(
                    command(["ip", "-j", "link", "show", "dev", host])
                )[0]["address"]
                peer_mac = json.loads(
                    command(["ip", "-n", namespace, "-j", "link", "show", "dev", peer])
                )[0]["address"]
                command(
                    [
                        "ip",
                        "-6",
                        "neigh",
                        "replace",
                        prefix + "::2",
                        "lladdr",
                        peer_mac,
                        "nud",
                        "permanent",
                        "dev",
                        host,
                    ]
                )
                command(
                    [
                        "ip",
                        "-n",
                        namespace,
                        "-6",
                        "neigh",
                        "replace",
                        prefix + "::1",
                        "lladdr",
                        host_mac,
                        "nud",
                        "permanent",
                        "dev",
                        peer,
                    ]
                )
            command(
                ["ip", "-n", namespace, "route", "add", "default", "via", subnet + ".1"]
            )
        command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if os.environ.get("DONINO_TEST_OVPN_SPLIT") != "1":
            command(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])
        command(
            ["nft", "-f", "-"],
            input='table ip donino_ovpn_test {\n chain forward {\n type filter hook forward priority filter; policy accept;\n iifname { "lab0", "lab1" } oifname "lab2" drop;\n }\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n ip saddr 10.67.0.0/24 oifname "lab2" masquerade;\n }\n}\n',
        )
        echo_source = root / "echo.py"
        echo_source.write_text("""import socketserver,threading
class Datagram(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        sock.sendto(data,self.client_address)
udp=socketserver.ThreadingUDPServer(('198.18.0.2',8083),Datagram)
threading.Thread(target=udp.serve_forever,daemon=True).start()
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(4)
            if not data: return
            self.request.sendall(data)
socketserver.ThreadingTCPServer(('198.18.0.2',8081),Echo).serve_forever()
""")
        processes.append(
            subprocess.Popen(
                ["ip", "netns", "exec", "origin", "/usr/bin/python3", str(echo_source)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        # HTTPServer performs a reverse DNS lookup during bind. The isolated
        # origin has no Internet DNS; TCPServer serves the same handler without it.
        http_source = root / "http_origin.py"
        http_source.write_text("""import functools,http.server,socketserver,sys
handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=sys.argv[1])
socketserver.ThreadingTCPServer(('198.18.0.2',8080),handler).serve_forever()
""")
        origin_log = open(root / "origin.log", "w+")
        process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                "origin",
                "/usr/bin/python3",
                str(http_source),
                str(root / "origin"),
            ],
            stdout=origin_log,
            stderr=origin_log,
        )
        processes.append(process)
        if os.environ.get("DONINO_TEST_OVPN_SPLIT") != "1":
            ipv6_source = root / "http6_origin.py"
            ipv6_source.write_text("""import functools,http.server,socketserver,socket,sys
class Server(socketserver.ThreadingTCPServer): address_family=socket.AF_INET6
handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=sys.argv[1])
Server(('fd42:200:2::2',8082),handler).serve_forever()
""")
            processes.append(
                subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        "origin",
                        "/usr/bin/python3",
                        str(ipv6_source),
                        str(root / "origin"),
                    ],
                    stdout=origin_log,
                    stderr=origin_log,
                )
            )

        def ipv6_probe(namespace):
            return subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "curl",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "2",
                    "--silent",
                    "--fail",
                    "http://[fd42:200:2::2]:8082/data",
                ],
                capture_output=True,
            )

        for _ in range(100):
            ready = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    "origin",
                    "curl",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "1",
                    "--silent",
                    "--fail",
                    "http://198.18.0.2:8080/data",
                ],
                capture_output=True,
            )
            if ready.returncode == 0 and (
                os.environ.get("DONINO_TEST_OVPN_SPLIT") == "1"
                or ipv6_probe("origin").returncode == 0
            ):
                break
            time.sleep(0.05)
        if ready.returncode != 0:
            origin_log.seek(0)
            raise AssertionError(
                (
                    "Origin failed before WG startup",
                    process.poll(),
                    ready.returncode,
                    origin_log.read(),
                    Path(f"/proc/{process.pid}/wchan").read_text(),
                    Path(f"/proc/{process.pid}/cmdline")
                    .read_bytes()
                    .replace(b"\0", b" ")
                    .decode(),
                    os.readlink(f"/proc/{process.pid}/ns/net"),
                    command(
                        [
                            "ip",
                            "netns",
                            "exec",
                            "origin",
                            "readlink",
                            "/proc/self/ns/net",
                        ]
                    ),
                    command(["ip", "netns", "exec", "origin", "cat", "/proc/net/tcp"]),
                    command(["ip", "-n", "origin", "-brief", "address"]),
                )
            )
        print("PASS: origin listener ready before OpenVPN startup", flush=True)
        if os.environ.get("DONINO_TEST_OVPN_SPLIT") != "1":
            probe = ipv6_probe("clienta")
            if probe.stdout != BODY:
                for args in (
                    ["ip", "-6", "route"],
                    ["ip", "-n", "clienta", "-6", "route"],
                    ["ip", "-n", "origin", "-6", "route"],
                    ["ip", "-6", "neigh"],
                    ["sysctl", "net.ipv6.conf.all.forwarding"],
                ):
                    print(command(args), flush=True)
                raise AssertionError(
                    ("Physical IPv6 baseline unavailable", probe.returncode)
                )
        with TestClient(app) as panel:
            with database() as db:
                db.execute(
                    "INSERT INTO admins VALUES(?,?,?)",
                    ("owner", hash_password("long-fixture-password"), "owner"),
                )
            panel.headers["X-Donino"] = "1"
            assert (
                panel.post(
                    "/api/login",
                    json={"username": "owner", "password": "long-fixture-password"},
                ).status_code
                == 200
            )
            node = panel.post(
                "/api/nodes", json={"name": "ovpn-lab", "host": "10.200.0.1"}
            ).json()
            user = panel.post("/api/users", json={"name": "two-ovpn-devices"}).json()
            device = panel.post(
                f"/api/users/{user['id']}/devices", json={"name": "second-device"}
            ).json()
            ep = panel.post(
                "/api/openvpn/endpoints",
                json={
                    "node_id": node["id"],
                    "name": "OpenVPN lab",
                    "host": "10.200.0.1",
                    "protocol": os.environ.get("DONINO_TEST_OVPN_PROTOCOL", "udp"),
                    # Explicit split-route acceptance for kernels without IPv6 ct-mark.
                    # Default CI still imports the unchanged full-tunnel profile.
                    "routes": ["198.18.0.0/30"]
                    if os.environ.get("DONINO_TEST_OVPN_SPLIT") == "1"
                    else ["0.0.0.0/0"],
                },
            ).json()
            assert (
                panel.put(
                    f"/api/openvpn/endpoints/{ep['id']}", json={"enabled": True}
                ).status_code
                == 200
            )
            peers = []
            for did in (user["id"], device["id"]):
                response = panel.post(
                    f"/api/openvpn/endpoints/{ep['id']}/peers",
                    json={"device_id": did},
                )
                assert response.status_code == 201
                peers.append(response.json())
            headers = {"Authorization": "Bearer " + node["token"]}

            class LocalPanel:
                def __init__(self):
                    self.confirmed_reports = []

                def get(self, path, **kwargs):
                    return panel.get(path, headers=headers, **kwargs)

                def post(self, path, **kwargs):
                    response = panel.post(path, headers=headers, **kwargs)
                    if response.is_success and kwargs.get("json", {}).get("usage"):
                        self.confirmed_reports.append(
                            (path, json.loads(json.dumps(kwargs["json"])))
                        )
                    return response

                def close(self):
                    pass

            identity = {
                "node_id": node["id"],
                "config_verify_key": public_material()["config_verify_key"],
                "expires": time.time() + 30 * 86400,
            }
            agent = OpenVPNAgent(client=LocalPanel(), identity=identity)
            try:
                marker = "dno" + ep["id"][:8]
                command(
                    [
                        "ip",
                        "link",
                        "add",
                        marker,
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "fixturepeer",
                    ]
                )
                try:
                    try:
                        agent.tick()
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(
                            "An existing foreign interface was adopted"
                        )
                    assert agent.kernel.exists(marker)
                finally:
                    command(["ip", "link", "delete", marker])
                agent.tick()
                client_processes = {}
                profile_texts = {}

                def connect_client(index):
                    namespace = ("clienta", "clientb")[index]
                    path = root / ("ovpc" + str(index) + ".ovpn")
                    log = root / ("client" + str(index) + ".log")
                    log.write_text("")
                    log.chmod(0o600)
                    child = subprocess.Popen(
                        [
                            "ip",
                            "netns",
                            "exec",
                            namespace,
                            "/usr/sbin/openvpn",
                            "--config",
                            str(path),
                            "--dev",
                            "ovpc" + str(index),
                            "--dev-type",
                            "tun",
                            "--log",
                            str(log),
                            "--verb",
                            "3",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    client_processes[index] = child
                    processes.append(child)
                    until = time.monotonic() + 12
                    while "Initialization Sequence Completed" not in log.read_text():
                        if child.poll() is not None or time.monotonic() > until:
                            for source in [
                                log,
                                *root.glob("node/runtime/*/server.log"),
                            ]:
                                lines = source.read_text()
                                lines = re.sub(
                                    r"-----BEGIN[\s\S]*?-----END[^\n]*-----",
                                    "[redacted-pem]",
                                    lines,
                                )
                                lines = re.sub(
                                    r"[A-Za-z0-9+/]{32,}={0,2}",
                                    "[redacted-material]",
                                    lines,
                                )
                                print(lines[-3000:], flush=True)
                            print(
                                "Failed client index/exit",
                                index,
                                child.poll(),
                                flush=True,
                            )
                            raise AssertionError(
                                "Real OpenVPN client startup failed; only redacted diagnostics emitted"
                            )
                        time.sleep(0.03)

                for index in (0, 1):
                    response = panel.get(
                        f"/api/openvpn/peers/{peers[index]['id']}/profile"
                    )
                    assert response.status_code == 200
                    path = root / ("ovpc" + str(index) + ".ovpn")
                    path.write_text(response.text)
                    profile_texts[index] = response.text
                    path.chmod(0o600)
                    connect_client(index)

                def reconnect(index=1):
                    child = client_processes[index]
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=5)
                    connect_client(index)

                def reject_profile(text, marker):
                    path, log = root / "rejected.ovpn", root / "rejected.log"
                    path.write_text(text)
                    path.chmod(0o600)
                    log.write_text("")
                    log.chmod(0o600)
                    child = subprocess.Popen(
                        [
                            "ip",
                            "netns",
                            "exec",
                            "clienta",
                            "/usr/sbin/openvpn",
                            "--config",
                            str(path),
                            "--dev",
                            "bad0",
                            "--dev-type",
                            "tun",
                            "--log",
                            str(log),
                            "--verb",
                            "3",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        until = time.monotonic() + 6
                        while True:
                            content = log.read_text()
                            assert "Initialization Sequence Completed" not in content, (
                                "Invalid client credentials unexpectedly connected"
                            )
                            if marker in content:
                                break
                            if child.poll() is not None or time.monotonic() > until:
                                raise AssertionError(
                                    "Negative TLS/auth control did not fail for the expected reason"
                                )
                            time.sleep(0.03)
                    finally:
                        if child.poll() is None:
                            child.terminate()
                        child.wait(timeout=4)

                def transfer(namespace, *, fail=False):
                    result = subprocess.run(
                        [
                            "ip",
                            "netns",
                            "exec",
                            namespace,
                            "curl",
                            "--noproxy",
                            "*",
                            "--max-time",
                            "4",
                            "--silent",
                            "--fail",
                            "http://198.18.0.2:8080/data",
                        ],
                        capture_output=True,
                    )
                    if fail:
                        assert result.returncode != 0, (
                            "Revoked OpenVPN traffic still passed"
                        )
                    else:
                        if result.returncode != 0 or result.stdout != BODY:
                            print(
                                "Transfer failure",
                                namespace,
                                result.returncode,
                                len(result.stdout),
                                flush=True,
                            )
                            for cmd in (
                                ["ip", "-n", namespace, "route"],
                                ["ip", "-s", "link", "show"],
                                ["nft", "list", "table", "ip", "donino_ovpn_test"],
                            ):
                                print(
                                    re.sub(
                                        r"[A-Za-z0-9+/]{43}=",
                                        "[redacted-key]",
                                        command(cmd),
                                    ),
                                    flush=True,
                                )
                            raise AssertionError("Real OpenVPN payload transfer failed")

                # Wait only for the origin listener, never retry the VPN transfer.
                for _ in range(100):
                    check = subprocess.run(
                        [
                            "ip",
                            "netns",
                            "exec",
                            "origin",
                            "curl",
                            "--noproxy",
                            "*",
                            "--silent",
                            "--fail",
                            "http://198.18.0.2:8080/data",
                        ],
                        capture_output=True,
                    )
                    if check.returncode == 0:
                        break
                    time.sleep(0.05)
                if check.returncode != 0:
                    origin_log.seek(0)
                    raise AssertionError(
                        (
                            "Origin listener failed",
                            process.poll(),
                            check.returncode,
                            check.stderr.decode(),
                            origin_log.read(),
                        )
                    )
                transfer("clienta")
                transfer("clientb")
                udp_probe = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b'donino-real-udp',('198.18.0.2',8083));assert s.recv(100)==b'donino-real-udp'"
                result = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        "clienta",
                        "/usr/bin/python3",
                        "-c",
                        udp_probe,
                    ],
                    capture_output=True,
                )
                assert result.returncode == 0, (
                    "Inner UDP payload did not traverse the VPN"
                )
                print(
                    "PASS: actual inner UDP payload round-trip through the VPN",
                    flush=True,
                )
                if os.environ.get("DONINO_TEST_OVPN_SPLIT") != "1":
                    assert ipv6_probe("clienta").returncode != 0, (
                        "Full-tunnel profile leaked via physical IPv6"
                    )
                    print(
                        "PASS: full-tunnel export blocked previously reachable physical IPv6",
                        flush=True,
                    )
                agent.tick()
                with database() as db:
                    used = db.execute(
                        "SELECT used FROM users WHERE id=?", (user["id"],)
                    ).fetchone()[0]
                    assert used > len(BODY) * 2
                    assert all(
                        r[0] > 0
                        for r in db.execute(
                            "SELECT uploaded+downloaded FROM devices WHERE user_id=?",
                            (user["id"],),
                        )
                    )
                # A fresh management snapshot can include native keepalive or
                # handshake bytes even with idle applications. Replay the exact
                # acknowledged reports to test dedup, never compare two different
                # live samples and mistake legitimate new bytes for duplication.
                confirmed = tuple(agent.client.confirmed_reports)
                assert confirmed
                for path, payload in confirmed:
                    panel.post(path, headers=headers, json=payload).raise_for_status()
                with database() as db:
                    assert (
                        db.execute(
                            "SELECT used FROM users WHERE id=?", (user["id"],)
                        ).fetchone()[0]
                        == used
                    )
                print(
                    "PASS: two real OpenVPN profiles, encrypted routing/NAT and per-device accounting/dedup ("
                    + (
                        "explicit split routes"
                        if os.environ.get("DONINO_TEST_OVPN_SPLIT") == "1"
                        else "full tunnel with IPv6 blocked"
                    )
                    + ")",
                    flush=True,
                )

                from app import openvpn_pki

                _, wrong_ca = openvpn_pki.authority("f" * 32)
                reject_profile(
                    re.sub(
                        r"<ca>[\s\S]*?</ca>",
                        "<ca>\n" + wrong_ca + "</ca>",
                        profile_texts[0],
                    ),
                    "VERIFY ERROR",
                )
                reject_profile(
                    profile_texts[0].replace(
                        "verify-x509-name donino-" + ep["id"] + " name",
                        "verify-x509-name wrong.example name",
                    ),
                    "VERIFY X509NAME ERROR",
                )
                transfer("clienta")
                transfer("clientb")
                print(
                    "PASS: incorrect CA and server identity refused; correct exported profiles stayed usable",
                    flush=True,
                )

                # Request/response on an existing socket avoids confusing bytes
                # buffered before revocation with new network traffic.
                script = """import socket,sys
s=socket.create_connection(('198.18.0.2',8081),timeout=3)
for line in sys.stdin:
    try:
        s.sendall(b'ping')
        assert s.recv(4)==b'ping'
        print('echo',flush=True)
    except (OSError,AssertionError):
        print('stopped',flush=True)
        break
"""
                stream = subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        "clienta",
                        "/usr/bin/python3",
                        "-c",
                        script,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                processes.append(stream)
                stream.stdin.write("ping\n")
                stream.stdin.flush()
                assert stream.stdout.readline().strip() == "echo"
                panel.put(
                    f"/api/openvpn/peers/{peers[0]['id']}", json={"enabled": False}
                )
                agent.tick()
                stream.stdin.write("ping\n")
                stream.stdin.flush()
                assert stream.stdout.readline().strip() == "stopped", (
                    "Revoked open socket still transferred"
                )
                stream.wait(timeout=4)
                transfer("clienta", fail=True)
                result = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        "clienta",
                        "/usr/bin/python3",
                        "-c",
                        udp_probe,
                    ],
                    capture_output=True,
                )
                assert result.returncode != 0, "Revoked inner UDP payload still passed"
                transfer("clientb")
                print(
                    "PASS: peer revocation stopped an open stream; other device retained access",
                    flush=True,
                )

                # Old leaf remains signed by the correct CA, so only the serial
                # allowlist can reject it after rotation. No CA swap hides this.
                panel.put(
                    "/api/openvpn/peers/" + peers[0]["id"], json={"enabled": True}
                )
                rotated = panel.post("/api/openvpn/peers/" + peers[0]["id"] + "/rotate")
                assert (
                    rotated.status_code == 200
                    and rotated.json()["serial"] != peers[0]["serial"]
                )
                agent.tick()
                reconnect(1)
                reject_profile(profile_texts[0], "AUTH_FAILED")
                fresh = panel.get("/api/openvpn/peers/" + peers[0]["id"] + "/profile")
                assert fresh.status_code == 200
                (root / "ovpc0.ovpn").write_text(fresh.text)
                reconnect(0)
                transfer("clienta")
                transfer("clientb")
                panel.put(
                    "/api/openvpn/peers/" + peers[0]["id"], json={"enabled": False}
                )
                agent.tick()
                transfer("clienta", fail=True)
                transfer("clientb")
                print(
                    "PASS: rotated serial rejected the old valid-CA certificate; replacement certificate transferred",
                    flush=True,
                )

                # Exercise the actual independent ExecStopPost CLI with live
                # owned links and no usable panel origin. The supervisor is
                # quiesced and releases its lock, as after process termination.
                agent.stop.set()
                agent.watchdog.join(timeout=3)
                agent.lock.close()
                name = "dno" + ep["id"][:8]
                assert agent.kernel.exists(name)
                origin = os.environ.pop("DONINO_PANEL_URL")
                try:
                    command(
                        [sys.executable, "-m", "agent.openvpn", "--cleanup"],
                        timeout=20,
                    )
                finally:
                    os.environ["DONINO_PANEL_URL"] = origin
                assert not agent.kernel.exists(name), (
                    "Offline CLI left its owned interface live"
                )
                agent.interfaces, agent.owned, agent.offsets = [], {}, {}
                agent.last_raw = {}
                agent.close()
                print(
                    "PASS: independent offline stop CLI withdrew live owned links and journaled counters",
                    flush=True,
                )
                # Restart preserves sampled usage, identity and credentials.
                with database() as db:
                    before = db.execute(
                        "SELECT used FROM users WHERE id=?", (user["id"],)
                    ).fetchone()[0]
                agent = OpenVPNAgent(client=LocalPanel(), identity=identity)
                agent.tick()
                reconnect()
                transfer("clientb")
                agent.tick()
                with database() as db:
                    assert (
                        db.execute(
                            "SELECT used FROM users WHERE id=?", (user["id"],)
                        ).fetchone()[0]
                        > before
                    )
                    db.execute(
                        "UPDATE users SET quota=used+16384 WHERE id=?", (user["id"],)
                    )
                agent.tick()
                # The local supervisor, rather than another panel sync, applies exhaustion.
                transfer("clientb")
                agent.enforce()
                transfer("clientb", fail=True)
                agent.report()
                print("PASS: restart/replay and local quota exhaustion", flush=True)

                with database() as db:
                    db.execute("UPDATE users SET quota=0 WHERE id=?", (user["id"],))
                assert (
                    panel.post(f"/api/users/{user['id']}/reset-traffic").status_code
                    == 200
                )
                agent.tick()
                reconnect()
                with database() as db:
                    row = db.execute(
                        "SELECT used,period_no FROM users WHERE id=?", (user["id"],)
                    ).fetchone()
                    assert row[0] == 0 and row[1] == 1
                transfer("clientb")
                agent.tick()
                with database() as db:
                    assert (
                        db.execute(
                            "SELECT used FROM users WHERE id=?", (user["id"],)
                        ).fetchone()[0]
                        > 0
                    )
                    assert (
                        db.execute(
                            "SELECT uploaded+downloaded FROM usage_periods WHERE user_id=? AND period_no=0",
                            (user["id"],),
                        ).fetchone()[0]
                        > 0
                    )
                print(
                    "PASS: period reset retained old bytes and charged new traffic to the new period",
                    flush=True,
                )

                with database() as db:
                    db.execute(
                        "UPDATE users SET quota=0,expires=? WHERE id=?",
                        (int(time.time()) + 3, user["id"]),
                    )
                agent.tick()
                transfer("clientb")
                # Watchdog sampling + process scheduling is not an exact 3.2s SLO.
                # Wait for its kernel withdrawal, without syncing the panel or
                # retrying application traffic, then attempt one new transfer.
                name = "dno" + ep["id"][:8]
                until = time.monotonic() + 6
                while any(
                    p["public_key"] == peers[1]["id"]
                    for interface in agent.interfaces
                    for p in interface["peers"]
                ):
                    if time.monotonic() >= until:
                        raise AssertionError(
                            "Expiry watchdog did not withdraw the peer"
                        )
                    time.sleep(0.05)
                transfer("clientb", fail=True)
                print(
                    "PASS: real-time expiry stopped traffic without another panel sync",
                    flush=True,
                )

                with database() as db:
                    db.execute(
                        "UPDATE users SET expires=NULL WHERE id=?", (user["id"],)
                    )
                agent.tick()
                reconnect()
                transfer("clientb")
                agent.deadline = time.monotonic() - 1
                agent.enforce()
                transfer("clientb", fail=True)
                print("PASS: expired signed authority removed owned links", flush=True)
                agent.tick()
                reconnect()
                transfer("clientb")
                from app import ops

                archive = root / "wg.backup"
                ops.backup(archive)
                ops.restore(archive, replace=True)
                agent.tick()
                transfer("clientb", fail=True)
                assert not agent.interfaces
                print(
                    "PASS: database restore disabled OpenVPN before explicit operator reactivation",
                    flush=True,
                )

            finally:
                agent.close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
        print(
            command(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${Package} ${Version}\n",
                    "openvpn",
                ]
            ).strip(),
            flush=True,
        )


if __name__ == "__main__":
    try:
        run()
    except OperationError as failure:
        print(
            re.sub(r"[A-Za-z0-9+/]{43}=", "[redacted-key]", failure.stderr), flush=True
        )
        raise
