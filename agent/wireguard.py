"""WireGuard supervisor. Requires a separate enrolled identity and NET_ADMIN.

Owns only recorded dnw* links. Forwarding/NAT are operator provisioned; no
global routes, sysctls or firewall rules are modified by this process.
"""

import argparse
import base64
import fcntl
import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path

import httpx

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from agent.identity import load_identity, panel_client, validate_origin
from agent.journal import UsageJournal
from agent.main import NodeAgent
from app.node_identity import private_bytes, verify_desired
from ops.common import atomic_write

log = logging.getLogger("donino-wireguard")


class OperationError(RuntimeError):
    def __init__(self, stderr):
        super().__init__("WireGuard operation failed; private diagnostics withheld")
        self.stderr = stderr


def command(args, *, input=None, timeout=10):
    result = subprocess.run(
        args, input=input, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode:
        raise OperationError(result.stderr)
    return result.stdout


class Kernel:
    def __init__(self):
        self.children = {}
        self.userspace = os.environ.get("DONINO_WG_USERSPACE", "")
        if self.userspace and (
            not Path(self.userspace).is_absolute()
            or not os.access(self.userspace, os.X_OK)
        ):
            raise ValueError(
                "Explicit userspace implementation must be an absolute executable"
            )

    def exists(self, name):
        rows = json.loads(command(["ip", "-j", "link", "show"]))
        return any(r["ifname"] == name for r in rows)

    def public_key(self, name):
        return command(["wg", "show", name, "public-key"]).strip()

    def check(self, interface, owned):
        name = interface["name"]
        if self.exists(name):
            if name not in owned or self.public_key(name) != owned[name]:
                raise ValueError("Refusing to adopt an unowned WireGuard link")
        else:
            pool = ipaddress.ip_network(interface["pool"])
            for route in json.loads(
                command(["ip", "-j", "-4", "route", "show", "table", "all"])
            ):
                if (
                    route.get("dst", "default") == "default"
                    or route.get("dev") in owned
                ):
                    continue
                if pool.overlaps(ipaddress.ip_network(route["dst"], strict=False)):
                    raise ValueError("WireGuard pool overlaps an existing host route")

    def create(self, interface, deadline):
        name = interface["name"]
        if self.exists(name):
            raise ValueError("Refusing to overwrite an existing link")
        try:
            self._create(interface, deadline)
        except Exception:
            child = self.children.pop(name, None)
            if child and child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            if self.exists(name) and self.public_key(name) in (
                "",
                "(none)",
                interface["public_key"],
            ):
                command(["ip", "link", "delete", "dev", name])
            raise

    def _create(self, interface, deadline):
        def apply(args):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Signed intent expired during apply")
            return command(args, timeout=min(3, remaining))

        name = interface["name"]
        if self.userspace:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "app/probe_runner.py"),
                    "--parent",
                    str(os.getpid()),
                    self.userspace,
                    "-f",
                    name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.children[name] = process
            until = min(deadline, time.monotonic() + 5)
            while not self.exists(name):
                if process.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError("Userspace WireGuard did not create its link")
                time.sleep(0.05)
            # TUN appears before the private UAPI socket is ready.
            while not Path("/run/wireguard", name + ".sock").is_socket():
                if process.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError(
                        "Userspace WireGuard control socket did not become ready"
                    )
                time.sleep(0.05)
        else:
            apply(["ip", "link", "add", "dev", name, "type", "wireguard"])
        text = (
            "[Interface]\nPrivateKey = "
            + interface["private_key"]
            + "\nListenPort = "
            + str(interface["port"])
            + "\n"
        )
        for peer in interface["peers"]:
            text += (
                "\n[Peer]\nPublicKey = "
                + peer["public_key"]
                + "\nPresharedKey = "
                + peer["preshared_key"]
                + "\nAllowedIPs = "
                + peer["address"]
                + "/32\n"
            )
        with tempfile.NamedTemporaryFile(mode="w", prefix="donino-wg-") as file:
            os.chmod(file.name, 0o600)
            file.write(text)
            file.flush()
            apply(["wg", "setconf", name, file.name])
        apply(["ip", "address", "add", interface["address"], "dev", name])
        apply(["ip", "link", "set", "dev", name, "mtu", "1420", "up"])

    def counters(self, name):
        rows = command(["wg", "show", name, "transfer"]).splitlines()
        result = {}
        for row in rows:
            key, rx, tx = row.split()
            result[key] = (int(rx), int(tx))
        return result

    def remove_peer(self, name, key):
        command(["wg", "set", name, "peer", key, "remove"])

    def down(self, name):
        command(["ip", "link", "set", "dev", name, "down"])

    def delete(self, name):
        command(["ip", "link", "delete", "dev", name])
        child = self.children.pop(name, None)
        if child:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("Invalid WireGuard key")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ValueError("Invalid WireGuard key")
    return raw


def validate_interfaces(interfaces):
    if not isinstance(interfaces, list) or len(interfaces) > 4:
        raise ValueError("Invalid interface set")
    names, networks, keys, ports = set(), [], set(), set()
    count = 0
    for interface in interfaces:
        iid = interface["id"]
        if (
            not re.fullmatch("[a-f0-9]{32}", iid)
            or interface["name"] != "dnw" + iid[:8]
            or interface["name"] in names
        ):
            raise ValueError("Invalid owned interface name")
        names.add(interface["name"])
        pool = ipaddress.ip_network(interface["pool"], strict=True)
        private = [
            ipaddress.ip_network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]
        if (
            pool.version != 4
            or not 16 <= pool.prefixlen <= 28
            or not any(pool.subnet_of(p) for p in private)
            or any(pool.overlaps(p) for p in networks)
        ):
            raise ValueError("Invalid or overlapping pool")
        networks.append(pool)
        if interface["address"] != f"{pool.network_address + 1}/{pool.prefixlen}":
            raise ValueError("Invalid server address")
        if (
            type(interface["port"]) is not int
            or not 1024 <= interface["port"] <= 65535
            or interface["port"] in ports
        ):
            raise ValueError("Invalid WireGuard listener")
        ports.add(interface["port"])
        public = base64.b64encode(
            X25519PrivateKey.from_private_bytes(key(interface["private_key"]))
            .public_key()
            .public_bytes_raw()
        ).decode()
        if public != interface["public_key"]:
            raise ValueError("Server key mismatch")
        addresses = set()
        for peer in interface["peers"]:
            count += 1
            if count > 128:
                raise ValueError("Too many peers")
            key(peer["public_key"])
            key(peer["preshared_key"])
            address = ipaddress.ip_address(peer["address"])
            if (
                address not in pool
                or address
                in (
                    pool.network_address,
                    pool.network_address + 1,
                    pool.broadcast_address,
                )
                or address in addresses
                or peer["public_key"] in keys
            ):
                raise ValueError("Duplicate peer or invalid peer address")
            addresses.add(address)
            keys.add(peer["public_key"])
            for field in ("device_id", "user_id"):
                if str(uuid.UUID(peer[field])) != peer[field]:
                    raise ValueError("Invalid device identity")
            if type(peer["period_no"]) is not int or peer["period_no"] < 0:
                raise ValueError("Invalid period")
            for field in ("remaining", "expires"):
                if peer[field] is not None and (
                    type(peer[field]) is not int or peer[field] < 0
                ):
                    raise ValueError("Invalid quota/expiry")


class WireGuardAgent:
    namespace = "wireguard"
    state_env = "DONINO_WG_STATE"
    default_state = "/var/lib/donino-wireguard"
    driver_factory = Kernel
    validate = staticmethod(validate_interfaces)
    # Reuse the enrolled-certificate renewal contract without the Xray runtime.
    renew_identity = NodeAgent.renew_identity

    def __init__(self, *, client=None, identity=None, kernel=None):
        self.base = validate_origin(os.environ["DONINO_PANEL_URL"].rstrip("/"))
        self.directory = Path(os.environ.get(self.state_env, self.default_state))
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = open(self.directory / "agent.lock", "a")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.identity = identity or load_identity(self.directory, self.base)
        if not self.identity:
            self.lock.close()
            raise ValueError("Enroll a separate VPN node identity before startup")
        self.client = client or panel_client(
            self.base, directory=self.directory, identity=self.identity
        )
        self.kernel = kernel or self.driver_factory()
        self.agent_instance = str(uuid.uuid4())
        self.renew_at = 0
        self.guard = threading.RLock()
        self.stop = threading.Event()
        self.deadline = 0
        self.revision = ""
        self.interfaces = []
        self.owned = {}
        self.offsets = {}
        self.last_raw = {}
        self.baseline = {}
        self.limits = {}
        self.epoch = str(uuid.uuid4())
        self.journal = UsageJournal(self.directory / (self.namespace + "-usage.db"))
        self.journal.bind(self.base, self.identity["node_id"] + "|" + self.namespace)
        state = self.directory / "active.json"
        if state.exists():
            saved = json.loads(private_bytes(state))
            self.validate(saved["interfaces"])
            self.interfaces, self.epoch, self.offsets = (
                saved["interfaces"],
                saved["epoch"],
                saved["offsets"],
            )
            self.last_raw = saved.get("last_raw", {})
            self.owned = {i["name"]: i["public_key"] for i in self.interfaces}
            if hasattr(self.kernel, "bind_epoch"):
                self.kernel.bind_epoch(self.epoch)
            self.stop_core()  # Snapshot surviving kernel counters before a fresh epoch.
        self.watchdog = threading.Thread(target=self.watch, daemon=True)
        self.watchdog.start()

    def save(self):
        atomic_write(
            self.directory / "active.json",
            json.dumps(
                {
                    "interfaces": self.interfaces,
                    "epoch": self.epoch,
                    "offsets": self.offsets,
                    "last_raw": self.last_raw,
                }
            ),
        )

    def snapshot(self):
        values = {d: dict(v) for d, v in self.offsets.items()}
        raw = {}
        for interface in self.interfaces:
            name = interface["name"]
            exists = self.kernel.exists(name)
            if not exists and not getattr(self.kernel, "retained_counters", False):
                continue
            if exists and self.kernel.public_key(name) != self.owned[name]:
                raise ValueError("Owned WireGuard link identity changed")
            counters = self.kernel.counters(name)
            for peer in interface["peers"]:
                up, down = counters.get(peer["public_key"], (0, 0))
                if min(up, down) < 0:
                    raise ValueError("Negative WireGuard counter")
                counter_key = name + "|" + peer["public_key"]
                previous = self.last_raw.get(counter_key, [0, 0])
                if up < previous[0] or down < previous[1]:
                    # Preserve observed pre-reset bytes; force a fresh kernel epoch.
                    offset = self.offsets.setdefault(
                        peer["device_id"],
                        {
                            "user_id": peer["device_id"],
                            "up": 0,
                            "down": 0,
                            "period_no": peer["period_no"],
                        },
                    )
                    offset["up"] += previous[0]
                    offset["down"] += previous[1]
                    observed = values.setdefault(
                        peer["device_id"],
                        {
                            "user_id": peer["device_id"],
                            "up": 0,
                            "down": 0,
                            "period_no": peer["period_no"],
                        },
                    )
                    observed["up"] += previous[0]
                    observed["down"] += previous[1]
                    self.revision = ""
                self.last_raw[counter_key] = [up, down]
                sample = values.setdefault(
                    peer["device_id"],
                    {
                        "user_id": peer["device_id"],
                        "up": 0,
                        "down": 0,
                        "period_no": peer["period_no"],
                    },
                )
                if sample["period_no"] != peer["period_no"]:
                    raise ValueError("A WireGuard epoch cannot mix device periods")
                sample["up"] += up
                sample["down"] += down
                raw[(name, peer["public_key"])] = (up, down)
        self.journal.record(self.epoch, list(values.values()))
        if hasattr(self.kernel, "flush_journal"):
            recorded = self.kernel.flush_journal()
            values = recorded.get(self.epoch, values)
        self.save()
        return values, raw

    def stop_core(self):
        with self.guard:
            for interface in self.interfaces:
                if self.kernel.exists(interface["name"]):
                    if (
                        self.kernel.public_key(interface["name"])
                        != self.owned[interface["name"]]
                    ):
                        raise ValueError("Refusing to stop an unowned link")
                    self.kernel.down(interface["name"])
            self.snapshot()
            for name in list(self.owned):
                if self.kernel.exists(name) or getattr(
                    self.kernel, "retained_counters", False
                ):
                    self.kernel.delete(name)
            if hasattr(self.kernel, "flush_journal"):
                self.kernel.flush_journal()
            self.interfaces, self.owned, self.offsets = [], {}, {}
            self.last_raw = {}
            self.revision = ""
            self.save()

    def report(self):
        with self.guard:
            values, _ = self.snapshot()
            epoch = self.epoch
        for _ in range(20):
            pending = self.journal.pending()
            if not pending:
                break
            eid, samples = pending
            response = self.client.post(
                f"/api/agent/{self.namespace}/heartbeat",
                json={"epoch": eid, "instance": self.agent_instance, "usage": samples},
            )
            response.raise_for_status()
            self.journal.acknowledge(eid, samples)
        if self.journal.pending():
            raise RuntimeError("Drain accounting backlog before renewing intent")
        response = self.client.post(
            f"/api/agent/{self.namespace}/heartbeat",
            json={"epoch": epoch, "instance": self.agent_instance, "usage": []},
        )
        response.raise_for_status()
        self.journal.prune(epoch)
        return values

    def remove_only(self, interfaces):
        """Withdraw peers without restarting unrelated live WireGuard sessions."""
        if not self.interfaces or len(interfaces) != len(self.interfaces):
            return False
        old = {i["id"]: i for i in self.interfaces}
        for new in interfaces:
            prior = old.get(new["id"])
            if prior is None or {k: v for k, v in prior.items() if k != "peers"} != {
                k: v for k, v in new.items() if k != "peers"
            }:
                return False
            peers = {
                p["public_key"]: {
                    k: v for k, v in p.items() if k not in ("remaining", "expires")
                }
                for p in prior["peers"]
            }
            if any(
                peers.get(p["public_key"])
                != {k: v for k, v in p.items() if k not in ("remaining", "expires")}
                for p in new["peers"]
            ):
                return False
        _, raw = self.snapshot()
        for new in interfaces:
            keep = {p["public_key"] for p in new["peers"]}
            prior = old[new["id"]]
            for peer in prior["peers"]:
                if peer["public_key"] in keep:
                    continue
                up, down = raw.get((prior["name"], peer["public_key"]), (0, 0))
                final = self.kernel.remove_peer(prior["name"], peer["public_key"])
                if final is not None:
                    up, down = final
                offset = self.offsets.setdefault(
                    peer["device_id"],
                    {
                        "user_id": peer["device_id"],
                        "up": 0,
                        "down": 0,
                        "period_no": peer["period_no"],
                    },
                )
                offset["up"] += up
                offset["down"] += down
                self.last_raw.pop(prior["name"] + "|" + peer["public_key"], None)
        self.interfaces = interfaces
        self.save()
        return True

    def tick(self):
        self.renew_identity()
        confirmed = self.report()
        result = self.client.get(
            f"/api/agent/{self.namespace}/config",
            params={"instance": self.agent_instance},
        )
        result.raise_for_status()
        path = self.directory / "verification.json"
        previous = json.loads(private_bytes(path)) if path.exists() else {}
        if previous.get("key") != self.identity["config_verify_key"]:
            previous = {}
        body = verify_desired(
            result.json(),
            self.identity["config_verify_key"],
            self.identity["node_id"],
            sequence=previous.get("sequence", 0),
        )
        if (
            body.get("kind") != self.namespace + "-v1"
            or body.get("agent_instance") != self.agent_instance
        ):
            raise ValueError("VPN intent belongs to another supervisor")
        if body["sequence"] == previous.get("sequence") and body[
            "revision"
        ] != previous.get("revision"):
            raise ValueError("A sequence cannot change revision")
        self.validate(body["interfaces"])
        atomic_write(
            path,
            json.dumps(
                {
                    "key": self.identity["config_verify_key"],
                    "sequence": body["sequence"],
                    "revision": body["revision"],
                }
            ),
        )
        with self.guard:
            missing = any(not self.kernel.exists(i["name"]) for i in self.interfaces)
            try:
                removed = (
                    not missing
                    and body["revision"] != self.revision
                    and self.remove_only(body["interfaces"])
                )
            except Exception:
                self.stop_core()
                raise
            if missing or (body["revision"] != self.revision and not removed):
                self.stop_core()
                for interface in body["interfaces"]:
                    self.kernel.check(interface, {})
                self.epoch = str(uuid.uuid4())
                if hasattr(self.kernel, "bind_epoch"):
                    self.kernel.bind_epoch(self.epoch)
                self.interfaces = body["interfaces"]
                self.owned = {i["name"]: i["public_key"] for i in self.interfaces}
                self.save()  # Own partial creations so failure/restart can safely remove them.
                try:
                    for interface in self.interfaces:
                        self.kernel.create(
                            interface,
                            time.monotonic()
                            + max(0, body["valid_until"] - time.time()),
                        )
                except Exception:
                    self.stop_core()
                    raise
                confirmed = {}
            else:
                # Refresh signed quota/expiry without disturbing kernel counters.
                self.interfaces = body["interfaces"]
            if hasattr(self.kernel, "refresh"):
                for interface in self.interfaces:
                    self.kernel.refresh(interface)
            self.baseline = {d: v["up"] + v["down"] for d, v in confirmed.items()}
            self.limits = {
                p["user_id"]: p["remaining"]
                for i in self.interfaces
                for p in i["peers"]
            }
            self.revision = body["revision"]
            self.deadline = time.monotonic() + max(
                0, min(60, body["valid_until"] - time.time())
            )
            self.save()

    def enforce(self):
        with self.guard:
            if self.interfaces and time.monotonic() >= self.deadline:
                self.stop_core()
                return
            values, raw = self.snapshot()
            spent = defaultdict(int)
            for interface in self.interfaces:
                for peer in interface["peers"]:
                    d = peer["device_id"]
                    if d in values:
                        # A device may have peers on more than one interface.
                        spent[peer["user_id"]] += max(
                            0,
                            values[d]["up"]
                            + values[d]["down"]
                            - self.baseline.get(d, 0),
                        )
                        values.pop(d)
            for interface in self.interfaces:
                keep = []
                for peer in interface["peers"]:
                    limit = self.limits.get(peer["user_id"])
                    expired = (
                        peer["expires"] is not None and peer["expires"] <= time.time()
                    )
                    if expired or (
                        limit is not None and spent[peer["user_id"]] >= limit
                    ):
                        up, down = raw.get(
                            (interface["name"], peer["public_key"]), (0, 0)
                        )
                        offset = self.offsets.setdefault(
                            peer["device_id"],
                            {
                                "user_id": peer["device_id"],
                                "up": 0,
                                "down": 0,
                                "period_no": peer["period_no"],
                            },
                        )
                        offset["up"] += up
                        offset["down"] += down
                        final = self.kernel.remove_peer(
                            interface["name"], peer["public_key"]
                        )
                        if final is not None:
                            offset["up"] += final[0] - up
                            offset["down"] += final[1] - down
                        self.last_raw.pop(
                            interface["name"] + "|" + peer["public_key"], None
                        )
                        self.revision = ""  # A fresh signed observation is required before readding.
                    else:
                        keep.append(peer)
                interface["peers"] = keep
            self.save()

    def watch(self):
        while not self.stop.wait(1):
            try:
                self.enforce()
            except Exception:
                try:
                    self.stop_core()
                except Exception:
                    log.error(
                        "VPN stop/accounting failed; operator intervention required"
                    )

    def close(self):
        self.stop.set()
        self.watchdog.join(timeout=2)
        self.stop_core()
        self.client.close()
        self.lock.close()

    @classmethod
    def cleanup(cls, directory=None, *, kernel=None):
        """Offline ExecStopPost: revoke owned links even if identity has expired.

        The lock excludes the live supervisor. Never enroll, contact the panel,
        or trust a link name without checking its saved public key.
        """
        directory = Path(directory or os.environ.get(cls.state_env, cls.default_state))
        if not directory.exists():
            return
        with open(directory / "agent.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = directory / "active.json"
            if not state.exists():
                return
            saved = json.loads(private_bytes(state))
            cls.validate(saved["interfaces"])
            agent = cls.__new__(cls)
            agent.directory = directory
            agent.guard = threading.RLock()
            agent.kernel = kernel or cls.driver_factory()
            agent.interfaces = saved["interfaces"]
            agent.owned = {i["name"]: i["public_key"] for i in agent.interfaces}
            agent.epoch = saved["epoch"]
            if hasattr(agent.kernel, "bind_epoch"):
                agent.kernel.bind_epoch(agent.epoch)
            agent.offsets = saved["offsets"]
            agent.last_raw = saved.get("last_raw", {})
            agent.journal = UsageJournal(directory / (cls.namespace + "-usage.db"))
            agent.stop_core()

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        try:
            while not self.stop.is_set():
                try:
                    self.tick()
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (401, 403):
                        self.stop_core()
                    log.warning("VPN authorization or synchronization failed")
                except Exception:
                    log.warning(
                        "VPN synchronization failed; signed deadline remains enforced"
                    )
                self.stop.wait(5)
        finally:
            self.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Offline cleanup of saved owned interfaces",
    )
    args = parser.parse_args()
    if args.cleanup:
        WireGuardAgent.cleanup()
    else:
        WireGuardAgent().run()
