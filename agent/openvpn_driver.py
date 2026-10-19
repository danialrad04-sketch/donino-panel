"""OpenVPN 2.6 management broker. Only private Unix management sockets are used.

Certificate verification stays in OpenVPN. The broker additionally checks the
signed allowlist's certificate serial before authorization. Session counters,
including final disconnect counters, are durably retained before aggregation.
"""

import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from agent.wireguard import Kernel, command
from app.node_identity import private_bytes
from ops.common import atomic_write


def quoted(value):
    value = str(value)
    if "\n" in value or "\r" in value:
        raise ValueError("Invalid private path")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def start_time(pid):
    # comm can contain spaces or parentheses; fields after its last ')' are fixed.
    return Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()[19]


class Channel:
    def __init__(self, driver, name, metadata, allowed, path):
        self.driver, self.name, self.metadata = driver, name, metadata
        self.allowed = {p["public_key"]: p for p in allowed}
        self.lock = threading.RLock()
        self.send_lock, self.query_lock = threading.Lock(), threading.Lock()
        self.finished = threading.Event()
        self.closed = threading.Event()
        self.clients = {}
        self.event = None
        self.environment = {}
        self.header = None
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        self.socket.connect(str(path))
        self.socket.settimeout(None)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        self.send("bytecount 1")
        self.send("hold release")

    def send(self, value):
        with self.send_lock:
            self.socket.sendall((value + "\n").encode())

    def record(self, cid, up, down):
        if not cid.isdecimal() or min(up, down) < 0:
            raise ValueError("Invalid management counter")
        with self.driver.connect() as db:
            db.execute(
                "UPDATE sessions SET up=MAX(up,?),down=MAX(down,?) WHERE instance=? AND cid=?",
                (up, down, self.metadata["instance"], cid),
            )

    def handle_event(self):
        kind, cid, *tail = self.event
        env = self.environment
        if not cid.isdecimal():
            raise ValueError("Invalid management session")
        if kind in ("CONNECT", "REAUTH"):
            kid = tail[0]
            if not kid.isdecimal():
                raise ValueError("Invalid management key id")
            name = env.get("common_name", "")
            serial = env.get("tls_serial_0", "")
            if not serial.isdecimal():
                try:
                    serial = str(
                        int(env.get("tls_serial_hex_0", "").replace(":", ""), 16)
                    )
                except ValueError:
                    serial = ""
            with self.lock:
                peer = self.allowed.get(name)
                if (
                    peer
                    and peer["serial"] == serial
                    and (peer["expires"] is None or peer["expires"] > time.time())
                ):
                    with self.driver.connect() as db:
                        db.execute(
                            "INSERT OR IGNORE INTO sessions VALUES(?,?,?,0,0)",
                            (self.metadata["instance"], cid, name),
                        )
                    self.clients[cid] = name
                    self.send(f"client-auth-nt {cid} {kid}")
                else:
                    self.send(f"client-deny {cid} {kid} not-authorized")
        elif kind == "DISCONNECT":
            self.record(
                cid,
                int(env.get("bytes_received", "0")),
                int(env.get("bytes_sent", "0")),
            )
            with self.lock:
                self.clients.pop(cid, None)

    def read(self):
        try:
            with self.socket.makefile("r", encoding="utf8") as stream:
                while not self.closed.is_set():
                    line = stream.readline(65537)
                    if not line or len(line) > 65536:
                        raise RuntimeError(
                            "Management connection ended or exceeded its bound"
                        )
                    line = line.rstrip("\r\n")
                    if line.startswith(">CLIENT:ENV,"):
                        if self.event is None:
                            raise ValueError("Unbound management environment")
                        text = line[len(">CLIENT:ENV,") :]
                        if text == "END":
                            self.handle_event()
                            self.event = None
                            self.environment = {}
                        elif "=" in text:
                            key, value = text.split("=", 1)
                            if len(self.environment) >= 256:
                                raise ValueError(
                                    "Management environment exceeded its bound"
                                )
                            self.environment[key] = value
                    elif line.startswith(">CLIENT:"):
                        value = line[len(">CLIENT:") :].split(",")
                        if value[0] in (
                            "CONNECT",
                            "REAUTH",
                            "DISCONNECT",
                            "ESTABLISHED",
                        ):
                            self.event = value
                            self.environment = {}
                    elif line.startswith(">BYTECOUNT_CLI:"):
                        cid, up, down = line.split(":", 1)[1].split(",")
                        self.record(cid, int(up), int(down))
                    elif line.startswith("HEADER\tCLIENT_LIST\t"):
                        self.header = line.split("\t")[2:]
                    elif line.startswith("CLIENT_LIST\t") and self.header:
                        row = dict(zip(self.header, line.split("\t")[1:]))
                        self.record(
                            row["Client ID"],
                            int(row["Bytes Received"]),
                            int(row["Bytes Sent"]),
                        )
                    elif line == "END":
                        self.finished.set()
        except Exception:
            if not self.closed.is_set():
                # Losing the sole authorization/counter broker must stop traffic.
                self.driver.fail_closed(self.metadata)
            self.finished.set()
            self.closed.set()

    def status(self):
        with self.query_lock:
            if self.closed.is_set():
                raise RuntimeError("Management broker is unavailable")
            self.finished.clear()
            self.send("status 3")
            if not self.finished.wait(3) or self.closed.is_set():
                raise RuntimeError("Management status deadline exceeded")

    def remove(self, key):
        with self.lock:
            self.allowed.pop(key, None)
            targets = [cid for cid, name in self.clients.items() if name == key]
            for cid in targets:
                self.send("client-kill " + cid)
        until = time.monotonic() + 3
        while True:
            self.status()  # OpenVPN orders status after final disconnect events.
            with self.lock:
                if not any(name == key for name in self.clients.values()):
                    break
            if time.monotonic() >= until:
                raise RuntimeError("OpenVPN session withdrawal timed out")
            time.sleep(0.03)

    def close(self):
        self.closed.set()
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
        self.thread.join(timeout=3)


class OpenVPNDriver:
    check = Kernel.check
    retained_counters = True

    def __init__(self):
        self.root = (
            Path(os.environ.get("DONINO_OVPN_STATE", "/var/lib/donino-openvpn"))
            / "runtime"
        )
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.binary = os.environ.get("DONINO_OPENVPN") or shutil.which("openvpn")
        if (
            not self.binary
            or not Path(self.binary).is_absolute()
            or not os.access(self.binary, os.X_OK)
        ):
            raise ValueError("An absolute OpenVPN 2.6 executable is required")
        self.binary = str(Path(self.binary).resolve())
        self.channels, self.children = {}, {}
        self.current_epoch = None
        self.database = self.root / "sessions.db"
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS sessions(instance TEXT,cid TEXT,peer TEXT,up INTEGER,down INTEGER,PRIMARY KEY(instance,cid))"
            )

    def bind_epoch(self, epoch):
        uuid.UUID(epoch)
        self.current_epoch = epoch

    def connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        os.chmod(self.database, 0o600)
        db.execute("PRAGMA synchronous=FULL")
        # sqlite connection context commits; explicitly close via a small wrapper.
        from contextlib import contextmanager

        @contextmanager
        def connection():
            try:
                with db:
                    yield db
            finally:
                db.close()

        return connection()

    def metadata(self, name):
        if not re.fullmatch("dno[a-f0-9]{8}", name):
            raise ValueError("Invalid owned name")
        return json.loads(private_bytes(self.root / name / "process.json"))

    def same_process(self, meta):
        try:
            args = Path(f"/proc/{meta['pid']}/cmdline").read_bytes().split(b"\0")
            return start_time(meta["pid"]) == meta["start"] and args[:3] == [
                meta["binary"].encode(),
                b"--config",
                meta["config"].encode(),
            ]
        except (OSError, ProcessLookupError):
            return False

    def exists(self, name):
        return any(
            r["ifname"] == name
            for r in json.loads(command(["ip", "-j", "link", "show"]))
        )

    def public_key(self, name):
        meta = self.metadata(name)
        if not self.same_process(meta):
            raise ValueError("Refusing to adopt an unowned OpenVPN process/link")
        return meta["fingerprint"]

    def fail_closed(self, meta):
        if self.same_process(meta):
            os.kill(meta["pid"], signal.SIGTERM)

    def create(self, i, deadline):
        if self.exists(i["name"]):
            raise ValueError("Refusing to replace an existing link")
        if not re.match(r"OpenVPN 2\.6\.", command([self.binary, "--version"])):
            raise ValueError("Only OpenVPN 2.6 has been selected for acceptance")
        folder = self.root / i["name"]
        folder.mkdir(exist_ok=True, mode=0o700)
        ccd = folder / "clients"
        ccd.mkdir(exist_ok=True, mode=0o700)
        for file in ccd.iterdir():
            if not file.is_file() or file.is_symlink():
                raise ValueError("Unsafe client directory entry")
            file.unlink()
        net = ipaddress.ip_network(i["pool"])
        for p in i["peers"]:
            atomic_write(
                ccd / p["public_key"], f"ifconfig-push {p['address']} {net.netmask}\n"
            )
        for field, file in (
            ("ca_cert", "ca.pem"),
            ("server_cert", "server.pem"),
            ("private_key", "server.key"),
            ("tls_key", "tls.key"),
        ):
            atomic_write(folder / file, i[field])
        sock = folder / "management.sock"
        if sock.exists():
            meta = self.metadata(i["name"])
            if self.same_process(meta):
                raise ValueError("An owned server is already running")
            sock.unlink()
        lines = [
            f"dev {i['name']}",
            "dev-type tun",
            "topology subnet",
            "proto " + ("udp4" if i["protocol"] == "udp" else "tcp4-server"),
            f"port {i['port']}",
            f"server {net.network_address} {net.netmask} nopool",
            "dh none",
            "disable-dco",
            "verify-client-cert require",
            "remote-cert-tls client",
            "tls-version-min 1.2",
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "auth SHA256",
            "allow-compression no",
            "max-clients 128",
            "keepalive 10 30",
            "verb 0",
            "management " + quoted(sock) + " unix",
            "management-hold",
            "management-client-auth",
            "auth-user-pass-optional",
            "client-config-dir " + quoted(ccd),
            "ccd-exclusive",
        ]
        for directive, file in (
            ("ca", "ca.pem"),
            ("cert", "server.pem"),
            ("key", "server.key"),
            ("tls-crypt", "tls.key"),
        ):
            lines.append(directive + " " + quoted(folder / file))
        config = folder / "server.conf"
        atomic_write(config, "\n".join(lines) + "\n")
        log = folder / "server.log"
        log.touch(mode=0o600)
        os.chmod(log, 0o600)
        with log.open("a") as output:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "app/probe_runner.py"),
                    "--parent",
                    str(os.getpid()),
                    self.binary,
                    "--config",
                    str(config),
                ],
                stdout=output,
                stderr=output,
            )
        self.children[i["name"]] = child
        meta = {
            "pid": child.pid,
            "start": start_time(child.pid),
            "fingerprint": i["public_key"],
            "instance": str(uuid.uuid4()),
            "epoch": self.current_epoch,
            "binary": self.binary,
            "config": str(config),
        }
        atomic_write(folder / "process.json", json.dumps(meta))
        try:
            until = min(deadline, time.monotonic() + 8)
            while not sock.is_socket():
                if child.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError(
                        "OpenVPN management startup failed; private diagnostics withheld"
                    )
                time.sleep(0.03)
            self.channels[i["name"]] = Channel(self, i["name"], meta, i["peers"], sock)
            while not self.exists(i["name"]):
                if child.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError(
                        "OpenVPN interface startup failed; private diagnostics withheld"
                    )
                time.sleep(0.03)
        except Exception:
            self.delete(i["name"])
            raise

    def counters(self, name):
        channel = self.channels.get(name)
        if channel and not channel.closed.is_set():
            channel.status()
        try:
            meta = self.metadata(name)
        except FileNotFoundError:
            if self.exists(name):
                raise ValueError("An unowned link has no private process metadata")
            return {}
        if meta.get("epoch") != self.current_epoch:
            return {}  # Old process counters must never enter a new usage epoch.
        with self.connect() as db:
            return {
                r[0]: (r[1], r[2])
                for r in db.execute(
                    "SELECT peer,SUM(up),SUM(down) FROM sessions WHERE instance=? GROUP BY peer",
                    (meta["instance"],),
                )
            }

    def refresh(self, interface):
        channel = self.channels.get(interface["name"])
        if channel:
            with channel.lock:
                channel.allowed = {p["public_key"]: p for p in interface["peers"]}

    def remove_peer(self, name, key):
        channel = self.channels.get(name)
        if not channel:
            raise RuntimeError("Missing management broker")
        channel.remove(key)
        return self.counters(name).get(key, (0, 0))

    def down(self, name):
        command(["ip", "link", "set", "dev", name, "down"])

    def delete(self, name):
        meta = self.metadata(name)
        if self.same_process(meta):
            os.kill(meta["pid"], signal.SIGTERM)
            until = time.monotonic() + 3
            while self.same_process(meta) and time.monotonic() < until:
                time.sleep(0.03)
            if self.same_process(meta):
                os.kill(meta["pid"], signal.SIGKILL)
        channel = self.channels.pop(name, None)
        if channel:
            channel.close()
        child = self.children.pop(name, None)
        if child:
            child.wait(timeout=3)
        # A TUN link disappears when its owner exits. Never delete a foreign link.
        if self.exists(name):
            raise ValueError("OpenVPN exit left a link requiring operator review")
