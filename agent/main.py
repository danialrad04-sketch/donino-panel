"""Pull-based node supervisor with durable accounting and live user updates."""

import copy
import fcntl
import json
import logging
import os
import re
import signal
import subprocess
import time
import uuid
import threading
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from app import __version__
from .journal import UsageJournal
from .live import user_additions
from .identity import load_identity, panel_client, certificate_request, save_identity
from app.node_identity import private_bytes, verify_desired
from ops.common import atomic_write

log = logging.getLogger("donino-node")


def parse_stats(data):
    users = {}
    for stat in data.get("stat", []):
        parts = stat.get("name", "").split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        if parts[3] not in ("uplink", "downlink"):
            continue
        value = int(stat.get("value", 0))
        if value < 0:
            raise ValueError("Negative Xray counter")
        user = users.setdefault(parts[1], {"user_id": parts[1], "up": 0, "down": 0})
        user["up" if parts[3] == "uplink" else "down"] = value
    return list(users.values())


class NodeAgent:
    def __init__(self):
        self.base = os.environ["DONINO_PANEL_URL"].rstrip("/")
        parsed = urlsplit(self.base)
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname
        ):
            raise ValueError("Panel URL must contain only an HTTPS origin")
        if parsed.scheme != "https" and parsed.hostname not in (
            "localhost",
            "127.0.0.1",
            "::1",
        ):
            raise ValueError("Panel URL must use HTTPS (HTTP only allowed on loopback)")
        self.max_stale = int(os.environ.get("DONINO_MAX_STALE_SECONDS", "120"))
        if self.max_stale < 15:
            raise ValueError("Maximum stale time must be at least 15 seconds")
        self.directory = Path(
            os.environ.get("DONINO_NODE_STATE", "node-state")
        ).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = open(self.directory / "agent.lock", "a")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise RuntimeError(
                "Another Donino agent owns this state directory"
            ) from None
        self.identity = load_identity(self.directory, self.base)
        self.client = panel_client(
            self.base,
            directory=self.directory,
            identity=self.identity,
            token=None if self.identity else os.environ["DONINO_NODE_TOKEN"],
        )
        self.proc_lock = threading.RLock()
        self.expiry_deadline = None
        self.candidate_deadline = None
        self.launch_deadline = None
        self.watchdog_stop = threading.Event()
        self.watchdog = None
        self.binary = os.environ.get("DONINO_XRAY", "/usr/local/bin/xray")
        self.journal = UsageJournal(self.directory / "usage.db")
        self.bound = False
        self.proc = None
        self.epoch = str(uuid.uuid4())
        self.revision = ""
        self.config = None
        self.periods = {}
        self.apply_mode = ""
        self.last_contact = time.monotonic()
        self.stop_requested = False
        self.interval = 5
        self.usage = []
        self.failed_revision = ""
        self.job_id = ""
        self.retry_at = 0
        self.renew_at = 0
        if self.identity:
            self.watchdog = threading.Thread(target=self.expiry_watchdog, daemon=True)
            self.watchdog.start()

    def running(self):
        process = self.proc
        return bool(process and process.poll() is None)

    def stop_core(self):
        with self.proc_lock:
            process, self.proc = self.proc, None
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def expiry_watchdog(self):
        while not self.watchdog_stop.wait(0.2):
            if (
                self.expiry_deadline is not None
                and time.monotonic() >= self.expiry_deadline
            ):
                self.stop_core()

    def validate_desired(self, desired):
        if not self.identity:
            return desired  # Legacy rollout remains explicit, until enrollment.
        path = self.directory / "verification.json"
        previous = json.loads(private_bytes(path)) if path.exists() else {}
        if previous.get("key") != self.identity["config_verify_key"]:
            previous = {}  # A newly authorized enrollment can pin a new signing root.
        body = verify_desired(
            desired,
            self.identity["config_verify_key"],
            self.identity["node_id"],
            sequence=previous.get("sequence", 0),
        )
        if body["sequence"] == previous.get("sequence") and body[
            "revision"
        ] != previous.get("revision"):
            raise ValueError(
                "The same config sequence cannot identify different revisions"
            )
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
        self.candidate_deadline = time.monotonic() + min(
            60, body["valid_until"] - time.time()
        )
        if body["revision"] == self.revision:
            self.expiry_deadline = self.candidate_deadline
        return desired

    def renew_identity(self):
        if (
            not self.identity
            or self.identity["expires"] > time.time() + 7 * 86400
            or time.monotonic() < self.renew_at
        ):
            return
        self.renew_at = time.monotonic() + 300
        private, csr = certificate_request()
        atomic_write(self.directory / "renewal-pending.key", private)
        response = self.client.post("/api/agent/renew-certificate", json={"csr": csr})
        response.raise_for_status()
        identity = save_identity(
            self.directory,
            self.base,
            self.identity["node_id"],
            response.json(),
            private,
        )
        replacement = panel_client(
            self.base, directory=self.directory, identity=identity
        )
        previous, self.client = self.client, replacement
        self.identity = identity
        previous.close()
        (self.directory / "renewal-pending.key").unlink(missing_ok=True)

    def snapshot(self):
        if self.running():
            result = subprocess.run(
                [
                    self.binary,
                    "api",
                    "statsquery",
                    "-s=127.0.0.1:10085",
                    "-pattern=user>>>",
                    "-reset=false",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                check=True,
            )
            self.usage = parse_stats(json.loads(result.stdout))
            for sample in self.usage:
                if sample["user_id"] in self.periods:
                    sample["period_no"] = self.periods[sample["user_id"]]
        self.journal.record(self.epoch, self.usage)
        return self.usage

    def write_config(self, path, config):
        temporary = path.with_name(path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump(config, file)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(path)

    def start_core(self, config):
        active = self.directory / "config.json"
        self.write_config(active, config)
        self.epoch = str(uuid.uuid4())
        self.usage = []
        with self.proc_lock:
            if self.identity and (
                self.launch_deadline is None or time.monotonic() >= self.launch_deadline
            ):
                raise RuntimeError("Signed config execution window has expired")
            self.expiry_deadline = self.launch_deadline
            self.proc = subprocess.Popen(
                [self.binary, "run", "-c", str(active)],
                stdout=subprocess.DEVNULL,
                stderr=None,
            )
        time.sleep(0.5)
        if not self.running():
            raise RuntimeError("Xray exited on startup; inspect the node service log")

    def api_command(self, command, args, expected):
        result = subprocess.run(
            [self.binary, "api", command, "-s=127.0.0.1:10085", "-t=5", *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        # Xray CLI can exit 0 even after partial failures. Check its success count.
        verb = "Added" if command == "adu" else "Removed"
        if not re.search(rf"{verb} {expected} user\(s\) in total\.", result.stdout):
            raise RuntimeError("Xray did not confirm every live user operation")

    def hot_apply(self, changes):
        for inbound, add in changes:
            if add:
                for offset in range(0, len(add), 100):
                    batch = add[offset : offset + 100]
                    value = copy.deepcopy(inbound)
                    value["settings"]["clients"] = batch
                    path = self.directory / "user-update.json"
                    self.write_config(path, {"inbounds": [value]})
                    self.api_command("adu", [str(path)], len(batch))
        self.snapshot()

    def apply(self, desired):
        previous_deadline = self.expiry_deadline
        config = desired["config"]
        periods = desired.get("periods", {})
        previous_periods = self.periods
        if not isinstance(periods, dict) or any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in periods.items()
        ):
            raise ValueError("Invalid usage period map")
        changed_period = any(
            periods.get(key) != value
            for key, value in self.periods.items()
            if key in periods
        )
        api = next((i for i in config["inbounds"] if i.get("tag") == "api"), None)
        if not api or api.get("listen") != "127.0.0.1" or api.get("port") != 10085:
            raise ValueError("Invalid local management endpoint")
        path = self.directory / "candidate.json"
        self.write_config(path, config)
        result = subprocess.run(
            [self.binary, "run", "-test", "-c", str(path)],
            capture_output=True,
            timeout=15,
        )
        if result.returncode:
            raise ValueError(
                "Xray config validation failed; check node certificates and Xray version"
            )
        self.report()
        changes = (
            user_additions(self.config, config)
            if self.config and self.running() and not changed_period
            else None
        )
        if changes is not None:
            try:
                self.periods = dict(periods)
                self.hot_apply(changes)
                self.write_config(self.directory / "config.json", config)
                self.config = copy.deepcopy(config)
                self.periods = dict(periods)
                self.revision = desired["revision"]
                self.apply_mode = "hot"
                self.expiry_deadline = self.candidate_deadline
                log.info("Applied live user update %s", self.revision[:12])
                return
            except Exception:
                log.warning(
                    "Live update failed; reconciling with a full config restart"
                )
                self.snapshot()
        previous, previous_revision = self.config, self.revision
        self.stop_core()
        try:
            self.launch_deadline = self.candidate_deadline
            self.start_core(config)
        except Exception:
            self.stop_core()
            if previous:
                try:
                    self.launch_deadline = previous_deadline
                    self.start_core(previous)
                    self.config = previous
                    self.periods = previous_periods
                    self.revision = previous_revision
                    self.apply_mode = "rollback"
                except Exception:
                    self.stop_core()
                    self.revision = ""
                    raise RuntimeError(
                        "Xray startup and rollback both failed"
                    ) from None
                raise RuntimeError(
                    "New config failed on startup; restored previous running config"
                ) from None
            self.revision = ""
            raise
        self.config = copy.deepcopy(config)
        self.periods = dict(periods)
        self.revision = desired["revision"]
        self.apply_mode = "restart"
        log.info("Applied revision %s", self.revision[:12])

    def authenticate_identity(self):
        result = self.client.get("/api/agent/config")
        result.raise_for_status()
        desired = self.validate_desired(result.json())
        node_id = desired.get("node_id")
        if not node_id:
            raise RuntimeError(
                "Upgrade the panel to 0.2 before upgrading its node agent"
            )
        self.journal.bind(self.base, node_id)
        self.bound = True

    def report(self, error=""):
        self.snapshot()  # Commit locally before any network operation.
        if not self.bound:
            self.authenticate_identity()
        for _ in range(20):
            pending = self.journal.pending()
            epoch, samples = pending if pending else (self.epoch, [])
            result = self.client.post(
                "/api/agent/heartbeat",
                json={
                    "epoch": epoch,
                    "applied_revision": self.revision,
                    "job_id": self.job_id,
                    "rejected_revision": self.failed_revision,
                    "usage": samples,
                    "error": error,
                    "agent_version": __version__,
                    "core_running": self.running(),
                    "apply_mode": self.apply_mode,
                    "pending_usage": self.journal.count(),
                },
            )
            result.raise_for_status()
            if not pending:
                break
            self.journal.acknowledge(epoch, samples)
        self.journal.prune(self.epoch)

    def tick(self):
        self.renew_identity()
        self.report()
        response = self.client.get("/api/agent/config")
        response.raise_for_status()
        desired = self.validate_desired(response.json())
        self.job_id = desired.get("job_id", "")
        if desired["revision"] != self.revision or not self.running():
            if (
                desired["revision"] == self.failed_revision
                and time.monotonic() < self.retry_at
            ):
                raise RuntimeError("Waiting before retrying rejected Xray revision")
            try:
                self.apply(desired)
                self.failed_revision = ""
            except Exception:
                self.failed_revision, self.retry_at = (
                    desired["revision"],
                    time.monotonic() + 30,
                )
                raise
        self.last_contact = time.monotonic()

    def close(self):
        self.watchdog_stop.set()
        if self.watchdog:
            self.watchdog.join(timeout=1)
        self.stop_core()
        if hasattr(self.client, "close"):
            self.client.close()
        self.lock.close()

    def run(self):
        def stop(*_):
            self.stop_requested = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            while not self.stop_requested:
                try:
                    self.tick()
                except Exception as error:
                    log.warning(
                        "Node synchronization failed (%s)", type(error).__name__
                    )
                    if isinstance(
                        error, httpx.HTTPStatusError
                    ) and error.response.status_code in (401, 403):
                        self.stop_core()
                    try:
                        self.report(
                            "Node synchronization or Xray error; inspect node service"
                        )
                    except Exception:
                        pass
                    if time.monotonic() - self.last_contact >= self.max_stale:
                        log.warning(
                            "Panel unavailable beyond grace period; stopping Xray"
                        )
                        self.stop_core()
                for _ in range(self.interval * 5):
                    if self.stop_requested:
                        break
                    time.sleep(0.2)
        finally:
            try:
                self.report("Node agent stopping")
            except Exception:
                pass
            self.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    NodeAgent().run()
