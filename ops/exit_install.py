"""Independent native Smart DNS exit role; no control DB or routing changes."""

import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import secrets
import shutil
import socket
import time
from pathlib import Path

from .common import InstallError, atomic_write, run, save_state
from .manifest import verify_manifest
from .preflight import domain_name, inspect
from .releases import prepare
from .tls import install_certificate, validate_certificate

SOURCE = Path(__file__).resolve().parent.parent
STATE = Path("/var/lib/donino-exit-installer/state.json")
CONFIG = Path("/etc/donino-smart-exit")
DATA = Path("/var/lib/donino-smart-exit")
BASE = Path("/opt/donino-smart-exit")
CURRENT = BASE / "current"
HTTP = Path("/etc/nginx/conf.d/donino-smart-exit.conf")
UNIT = Path("/etc/systemd/system/donino-smart-exit.service")
HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/donino-smart-exit")
USER = "donino-exit"


def settings(args, state):
    domain = domain_name(args.domain or state.get("domain") or "")
    if state.get("domain") and domain != state["domain"]:
        raise InstallError(
            "Exit domain migration requires a separate certificate/configuration procedure"
        )
    domains = sorted(
        {domain_name(d) for d in (args.exit_allow_domain or state.get("domains", []))}
    )
    if not 1 <= len(domains) <= 2000:
        raise InstallError("Supply 1–2000 explicit --exit-allow-domain suffixes")
    try:
        listen = str(
            ipaddress.ip_address(args.exit_listen or state.get("listen", "0.0.0.0"))
        )
    except ValueError as exc:
        raise InstallError("Exit listener must be an IP address") from exc
    if "%" in listen or ipaddress.ip_address(listen).is_multicast:
        raise InstallError("Invalid exit listener")
    port = args.exit_port if args.exit_port is not None else state.get("port", 9445)
    if not 1 <= port <= 65535 or port == 80:
        raise InstallError(
            "Exit TLS port must be valid and separate from HTTP-01 port 80"
        )
    return {"domain": domain, "domains": domains, "listen": listen, "port": port}


def http_config(domain, ipv6):
    return f"""# Managed Donino Smart DNS exit HTTP-01 vhost.
server {{
    listen 80;
    {"listen [::]:80;" if ipv6 else ""}
    server_name {domain_name(domain)};
    location ^~ /.well-known/acme-challenge/ {{ root /var/lib/donino-exit-acme; }}
    location / {{ return 404; }}
}}
"""


def credential(previous, config):
    """Retain the same secret across upgrades; never put it on a command line."""
    if previous is not None:
        if not isinstance(previous, dict) or not all(
            isinstance(previous.get(key), str) for key in ("username", "password")
        ):
            raise InstallError("Existing private exit credential is invalid")
        if not (
            12 <= len(previous.get("username", "")) <= 64
            and 12 <= len(previous.get("password", "")) <= 128
        ):
            raise InstallError("Existing private exit credential is invalid")
        if any(
            not 33 <= ord(c) <= 126 for c in previous["username"] + previous["password"]
        ):
            raise InstallError("Existing exit credential is not printable ASCII")
        result = dict(previous)
    else:
        result = {
            "username": secrets.token_hex(12),
            "password": secrets.token_urlsafe(32),
        }
    return {
        **result,
        "host": config["domain"],
        "sni": config["domain"],
        "port": config["port"],
    }


class ExitInstaller:
    def __init__(self, args):
        self.args = args
        self.state = (
            json.loads(STATE.read_text())
            if STATE.exists()
            else {"format": "donino-smart-exit-v1", "completed": []}
        )
        if self.state.get("format") != "donino-smart-exit-v1":
            raise InstallError("Unknown exit installer state")
        self.args.tls = self.args.tls or self.state.get("tls", "acme")

    def checkpoint(self, stage):
        self.state["last_stage"] = stage
        self.state["updated_at"] = int(time.time())
        if stage not in self.state["completed"]:
            self.state["completed"].append(stage)
        save_state(STATE, self.state)

    def managed_write(self, path, content, mode=0o644):
        atomic_write(path, content, mode)
        self.state.setdefault("managed_files", {})[str(path)] = hashlib.sha256(
            Path(path).read_bytes()
        ).hexdigest()
        save_state(STATE, self.state)

    def check_inventory(self):
        inventory = self.state.get("managed_files", {})
        for path in (HTTP, UNIT, HOOK):
            if (
                path.exists()
                and inventory.get(str(path))
                != hashlib.sha256(path.read_bytes()).hexdigest()
            ):
                raise InstallError(
                    "Refusing to overwrite unmanaged or modified exit configuration"
                )

    def packages(self):
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        run(["apt-get", "update"], env=env, code=3)
        run(
            [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "python3",
                "python3-venv",
                "ca-certificates",
                "openssl",
                "dbus",
                *(["nginx", "certbot"] if self.args.tls == "acme" else []),
            ],
            env=env,
            code=3,
        )
        run(["systemctl", "start", "dbus"])
        try:
            user = pwd.getpwnam(USER)
        except KeyError:
            run(
                [
                    "useradd",
                    "--system",
                    "--home-dir",
                    str(DATA),
                    "--shell",
                    "/usr/sbin/nologin",
                    USER,
                ]
            )
            user = pwd.getpwnam(USER)
            self.state["service_user"] = True
            self.checkpoint("user")
        else:
            if not self.state.get("service_user"):
                raise InstallError(
                    "Refusing to adopt an existing unmanaged exit service user"
                )
        if DATA.is_symlink():
            raise InstallError("Refusing a symbolic exit data directory")
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(DATA, user.pw_uid, user.pw_gid)
        os.chmod(DATA, 0o700)

    def proxy(self):
        previous = HTTP.read_bytes() if HTTP.exists() else None
        inventory = dict(self.state.get("managed_files", {}))
        try:
            self.managed_write(
                HTTP, http_config(self.state["domain"], self.state["ipv6"])
            )
            run(["nginx", "-t"], capture=True)
            run(["systemctl", "enable", "--now", "nginx"])
            run(["systemctl", "reload", "nginx"])
        except BaseException:
            if previous is None:
                HTTP.unlink(missing_ok=True)
            else:
                atomic_write(HTTP, previous, 0o644)
            self.state["managed_files"] = inventory
            save_state(STATE, self.state)
            raise

    def certificate(self):
        if self.args.tls == "existing":
            cert = self.args.cert_file or CONFIG / "tls/panel.crt"
            key = self.args.key_file or CONFIG / "tls/panel.key"
        else:
            Path("/var/lib/donino-exit-acme").mkdir(
                parents=True, exist_ok=True, mode=0o755
            )
            self.proxy()
            command = [
                "certbot",
                "certonly",
                "--webroot",
                "--webroot-path",
                "/var/lib/donino-exit-acme",
                "--non-interactive",
                "--agree-tos",
                "--keep-until-expiring",
                "--cert-name",
                "donino-smart-exit",
                "-d",
                self.state["domain"],
            ]
            command += (
                ["--email", self.args.email]
                if self.args.email
                else ["--register-unsafely-without-email"]
            )
            if self.args.acme_staging:
                command.append("--staging")
            run(command, code=5)
            cert, key = (
                Path("/etc/letsencrypt/live/donino-smart-exit/fullchain.pem"),
                Path("/etc/letsencrypt/live/donino-smart-exit/privkey.pem"),
            )
        ca = self.args.ca_file or (
            CONFIG / "ca.pem" if (CONFIG / "ca.pem").exists() else None
        )
        install_certificate(self.state["domain"], cert, key, CONFIG / "tls", ca_file=ca)
        if self.args.ca_file:
            atomic_write(CONFIG / "ca.pem", self.args.ca_file.read_bytes())
        self.state["tls"] = self.args.tls
        self.checkpoint("certificate")

    def private(self, module, destination, payload):
        # Root never writes through an application-owned path or symlink.
        run(
            [
                "runuser",
                "-u",
                USER,
                "--",
                str(CURRENT / ".venv/bin/python"),
                "-m",
                module,
                str(destination),
            ],
            input=json.dumps(payload),
            capture=True,
            cwd=CURRENT,
        )

    def sync_tls(self):
        self.private(
            "agent.dns_tls",
            DATA / "tls",
            {
                name: (CONFIG / "tls" / name).read_text()
                for name in ("panel.crt", "panel.key")
            },
        )

    def stored_access(self):
        path = CONFIG / "gateway-access.json"
        if not path.exists():
            if "configured" in self.state.get("completed", []):
                raise InstallError(
                    "Private exit credential is missing; automatic replacement refused"
                )
            return None
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            raise InstallError("Private exit credential could not be read") from exc

    def worker_config(self, access):
        return {
            "listen": self.state["listen"],
            "port": self.state["port"],
            "domains": self.state["domains"],
            "username": access["username"],
            "password_hash": hashlib.sha256(access["password"].encode()).hexdigest(),
            "tls_cert": str(DATA / "tls/current/panel.crt"),
            "tls_key": str(DATA / "tls/current/panel.key"),
        }

    def health(self):
        host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(
            self.state["listen"], self.state["listen"]
        )
        run(
            [
                str(CURRENT / ".venv/bin/python"),
                "-c",
                """import asyncio,json,sys,time
from app.smart_wire import close,connect_exit
config=json.load(open(sys.argv[1]))
config['host']=sys.argv[2]
async def check():
    deadline=time.monotonic()+30
    while True:
        writer=None
        try:
            _,writer=await connect_exit(config,ca=sys.argv[3] or None)
            return
        except Exception:
            if time.monotonic()>=deadline:
                raise RuntimeError('Exit TLS/auth readiness check failed') from None
            await asyncio.sleep(0.25)
        finally:
            await close(writer)
asyncio.run(check())
""",
                str(CONFIG / "gateway-access.json"),
                host,
                str(CONFIG / "ca.pem") if (CONFIG / "ca.pem").exists() else "",
            ],
            capture=True,
            cwd=CURRENT,
        )

    def install(self):
        desired = settings(self.args, self.state)
        report = inspect(
            desired["domain"],
            expected=self.args.expected_ip,
            existing=bool(self.state.get("domain")),
            allow_nginx=self.args.allow_existing_nginx,
            ports=(80,) if self.args.tls == "acme" else (),
        )
        if report["errors"]:
            raise InstallError("; ".join(report["errors"]))
        self.check_inventory()
        if not STATE.exists() and (
            BASE.exists()
            or CONFIG.exists()
            or DATA.is_symlink()
            or (DATA.exists() and any(DATA.iterdir()))
        ):
            raise InstallError(
                "Unmanaged exit files detected; automatic adoption refused"
            )
        if not UNIT.exists() or any(
            desired[k] != self.state.get(k) for k in ("listen", "port")
        ):
            family = socket.AF_INET6 if ":" in desired["listen"] else socket.AF_INET
            with socket.socket(family) as sock:
                try:
                    sock.bind((desired["listen"], desired["port"]))
                except OSError as exc:
                    raise InstallError(
                        "Exit listen address is occupied; existing services were not stopped"
                    ) from exc
        verify_manifest(
            SOURCE,
            expected=self.args.source_sha256,
            development=self.args.development_source,
        )
        access = credential(self.stored_access(), desired)
        if self.args.tls == "existing":
            cert, key = (
                self.args.cert_file or CONFIG / "tls/panel.crt",
                self.args.key_file or CONFIG / "tls/panel.key",
            )
            if not cert.is_file() or not key.is_file():
                raise InstallError(
                    "Existing TLS requires certificate and private key files", 5
                )
            if shutil.which("openssl"):
                validate_certificate(
                    desired["domain"],
                    cert,
                    key,
                    ca_file=self.args.ca_file
                    or (CONFIG / "ca.pem" if (CONFIG / "ca.pem").exists() else None),
                )
        self.state.update(desired, ipv6=report["ipv6"])
        self.checkpoint("preflight")
        CONFIG.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.packages()
        release = prepare(
            SOURCE,
            BASE,
            expected=self.args.source_sha256,
            development=self.args.development_source,
        )
        self.certificate()
        if UNIT.exists():
            run(["systemctl", "stop", "donino-smart-exit"])
        pending = BASE / ".current-next"
        pending.unlink(missing_ok=True)
        pending.symlink_to(release, target_is_directory=True)
        os.replace(pending, CURRENT)
        self.state["release"] = str(release)
        self.sync_tls()
        atomic_write(CONFIG / "gateway-access.json", json.dumps(access) + "\n")
        self.private(
            "agent.smart_config", DATA / "exit.json", self.worker_config(access)
        )
        unit = (SOURCE / "deploy/donino-smart-exit.service").read_text()
        if self.state["port"] >= 1024:
            unit = unit.replace(
                "AmbientCapabilities=CAP_NET_BIND_SERVICE", "AmbientCapabilities="
            ).replace(
                "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet="
            )
        self.managed_write(UNIT, unit)
        if self.state["tls"] == "acme":
            self.managed_write(
                HOOK,
                "#!/bin/sh\nset -eu\ncd /opt/donino-smart-exit/current\nexec /opt/donino-smart-exit/current/.venv/bin/python -m ops.install renew-certificate --role smart-exit\n",
                0o755,
            )
            run(["systemctl", "enable", "--now", "certbot.timer"])
        self.checkpoint("configured")
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "donino-smart-exit"])
        run(["systemctl", "restart", "donino-smart-exit"])
        self.health()
        self.checkpoint("complete")
        print(
            "Smart DNS exit installed. Private panel connection details: /etc/donino-smart-exit/gateway-access.json (root only)."
        )

    def renew(self):
        lineage = Path(
            os.environ.get("RENEWED_LINEAGE", "/etc/letsencrypt/live/donino-smart-exit")
        )
        if lineage.name != "donino-smart-exit":
            return
        if not self.state.get("domain") or not CURRENT.is_symlink():
            raise InstallError("No managed exit to renew")

        activated = False

        def activate():
            nonlocal activated
            activated = True
            self.sync_tls()
            run(["systemctl", "restart", "donino-smart-exit"])
            self.health()

        try:
            install_certificate(
                self.state["domain"],
                lineage / "fullchain.pem",
                lineage / "privkey.pem",
                CONFIG / "tls",
                ca_file=CONFIG / "ca.pem" if (CONFIG / "ca.pem").exists() else None,
                reload=activate,
            )
        except BaseException:
            if activated:
                self.sync_tls()
                run(["systemctl", "restart", "donino-smart-exit"])
            raise
        self.checkpoint("complete")

    def uninstall(self):
        self.check_inventory()
        if not self.state.get("managed_files"):
            raise InstallError("No managed exit inventory")
        if any(
            name not in {str(HTTP), str(UNIT), str(HOOK)}
            for name in self.state["managed_files"]
        ):
            raise InstallError("Unknown managed exit file")
        if UNIT.exists():
            run(["systemctl", "disable", "--now", "donino-smart-exit"])
        for name in self.state["managed_files"]:
            Path(name).unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
        if str(HTTP) in self.state["managed_files"] and shutil.which("nginx"):
            run(["nginx", "-t"], capture=True)
            run(["systemctl", "reload", "nginx"])
        self.checkpoint("uninstalled")
        print(
            "Exit services removed; private configuration, credentials, certificates and releases were preserved."
        )


def main(args):
    if (
        args.with_dns
        or args.with_tunnel_monitor
        or args.without_tunnel_monitor
        or args.with_smart_dns
        or args.smart_dns_ip
        or any(v is not None for v in (args.dns_listen, args.dns_port, args.dot_port))
    ):
        raise InstallError(
            "DNS/control gateway options cannot configure an independent exit role"
        )
    if args.command not in {
        "plan",
        "install",
        "upgrade",
        "repair",
        "doctor",
        "renew-certificate",
        "uninstall",
    }:
        raise InstallError(
            "This command is not supported by the independent smart-exit role"
        )
    installer = ExitInstaller(args)
    if args.command == "plan":
        desired = settings(args, installer.state)
        report = inspect(
            desired["domain"],
            expected=args.expected_ip,
            existing=bool(installer.state.get("domain")),
            allow_nginx=args.allow_existing_nginx,
            ports=(80,) if args.tls == "acme" else (),
        )
        report.update(
            role="smart-exit",
            database=None,
            exit=desired,
            required_public_ports=(["80/tcp"] if args.tls == "acme" else [])
            + [str(desired["port"]) + "/tcp"],
        )
        print(json.dumps(report, indent=2))
        return 2 if report["errors"] else 0
    if os.geteuid() != 0:
        raise InstallError("Run exit installation/maintenance as root")
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(STATE.parent / "install.lock", "a") as lock:
        os.chmod(STATE.parent / "install.lock", 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError("Another exit installer is running", 7) from exc
        if args.command == "uninstall":
            installer.uninstall()
        elif args.command == "renew-certificate":
            installer.renew()
        elif args.command == "doctor":
            if installer.state.get("last_stage") != "complete":
                raise InstallError("Exit installation is not complete", 6)
            installer.health()
            print(
                json.dumps(
                    {
                        "role": "smart-exit",
                        "domain": installer.state["domain"],
                        "port": installer.state["port"],
                        "tls_auth": "ok",
                        "application_verified": False,
                    }
                )
            )
        else:
            if args.command == "repair":
                args.tls = installer.state.get("tls", "acme")
            installer.install()
    return 0
