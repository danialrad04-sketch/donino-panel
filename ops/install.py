"""Idempotent native control-plane installer. No third-party imports at bootstrap."""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import secrets
import shutil
import socket
import sys
import time
import urllib.request
from pathlib import Path

from .common import InstallError, atomic_write, read_env, run, save_state
from .manifest import source_inventory, verify_manifest
from .preflight import domain_name, inspect
from .tls import install_certificate, validate_certificate
from . import smart_front, tunnel_monitor as monitor_ops

SOURCE = Path(__file__).resolve().parent.parent
STATE = Path("/var/lib/donino-installer/state.json")
CONFIG = Path("/etc/donino")
DATA = Path("/var/lib/donino-panel")
CURRENT = Path("/opt/donino-panel/current")


def nginx_config(domain, *, tls=False, ipv6=True, smart=False, plain=False):
    domain = domain_name(domain)
    common = """
    client_max_body_size 2m;
    location = /dns-query {
        access_log off;
        client_max_body_size 4k;
        include /etc/nginx/snippets/donino-proxy.conf;
    }
    location ~ ^/(sub|u|qr|api/portal)/ {
        access_log off;
        include /etc/nginx/snippets/donino-proxy.conf;
    }
    location / { include /etc/nginx/snippets/donino-proxy.conf; }
"""
    http = f"""server {{
    listen 80;
    {"listen [::]:80;" if ipv6 else ""}
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{ root /var/lib/donino-acme; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""
    if plain:
        # Explicit HTTP-only panel: no certificate and no redirect. Cookies
        # and passwords travel unencrypted; the installer warns the operator.
        return f"""server {{
    listen 80;
    {"listen [::]:80;" if ipv6 else ""}
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{ root /var/lib/donino-acme; }}
{common}
}}
"""
    if not tls:
        return http
    return (
        http
        + f"""server {{
    {"listen 127.0.0.1:8443 ssl proxy_protocol;" if smart else "listen 443 ssl;"}
    {"listen [::]:443 ssl;" if ipv6 and not smart else ""}
    {"set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol; real_ip_recursive off;" if smart else ""}
    server_name {domain};
    ssl_certificate /etc/donino/tls/panel.crt;
    ssl_certificate_key /etc/donino/tls/panel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_client_certificate /var/lib/donino-panel/pki/node-ca.crt;
    ssl_verify_client optional;
    ssl_verify_depth 2;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=15552000" always;
{common}
}}
"""
    )


PROXY = """proxy_pass http://127.0.0.1:8000;
proxy_http_version 1.1;
proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header Connection "";
proxy_read_timeout 60s;
"""


def dns_options(args, state):
    previous = state.get("dns", {})
    if not (args.with_dns or previous):
        if any(v is not None for v in (args.dns_listen, args.dns_port, args.dot_port)):
            raise InstallError("DNS listen options require --with-dns")
        return None
    listen = str(
        ipaddress.ip_address(args.dns_listen or previous.get("listen", "127.0.0.1"))
    )
    port = args.dns_port if args.dns_port is not None else previous.get("port", 5353)
    dot_port = (
        args.dot_port if args.dot_port is not None else previous.get("dot_port", 8530)
    )
    if (
        not (1 <= port <= 65535 and 1 <= dot_port <= 65535)
        or port == dot_port
        or 5335 in (port, dot_port)
    ):
        raise InstallError(
            "DNS/DoT ports must be distinct, valid and separate from upstream 5335"
        )
    return {"listen": listen, "port": port, "dot_port": dot_port}


def available_dns_ports(settings, *, include_upstream=True):
    for host, port, protocols in (
        (settings["listen"], settings["port"], (socket.SOCK_DGRAM, socket.SOCK_STREAM)),
        (settings["listen"], settings["dot_port"], (socket.SOCK_STREAM,)),
        *(
            ([("127.0.0.1", 5335, (socket.SOCK_DGRAM, socket.SOCK_STREAM))])
            if include_upstream
            else []
        ),
    ):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        for protocol in protocols:
            with socket.socket(family, protocol) as sock:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    sock.bind((host, port))
                except OSError as exc:
                    raise InstallError(
                        f"DNS listen address unavailable: {host}:{port}; existing services are not stopped"
                    ) from exc


class Installer:
    def __init__(self, args):
        self.args = args
        self.state = (
            json.loads(STATE.read_text())
            if STATE.exists()
            else {"format": 1, "completed": []}
        )

    def checkpoint(self, name):
        self.state["last_stage"] = name
        self.state["updated_at"] = int(time.time())
        if name not in self.state["completed"]:
            self.state["completed"].append(name)
        save_state(STATE, self.state)

    def managed_write(self, path, content, mode=0o644):
        atomic_write(path, content, mode)
        self.state.setdefault("managed_files", {})[str(path)] = hashlib.sha256(
            Path(path).read_bytes()
        ).hexdigest()

    def backup(self, *, release=None, destination=None):
        release = release or CURRENT
        destination = destination or Path("/var/backups/donino") / (
            time.strftime("donino-%Y%m%dT%H%M%SZ-", time.gmtime())
            + secrets.token_hex(4)
            + ".dnb"
        )
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.parent == Path("/var/backups/donino"):
            os.chown(destination.parent, 0, 0)
            os.chmod(destination.parent, 0o700)
        command = [
            str(release / ".venv/bin/python"),
            "-m",
            "ops.backup",
            "create",
            str(destination),
            "--key-file",
            str(self.args.backup_key_file),
        ]
        run(command, cwd=release, capture=True)
        self.state["last_backup"] = str(destination)
        self.state["last_backup_at"] = int(time.time())
        save_state(STATE, self.state)
        return destination

    def backup_timer(self):
        self.managed_write(
            "/etc/systemd/system/donino-backup.service",
            """[Unit]
Description=Encrypted Donino control-plane backup
After=postgresql.service
[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/donino-panel/current
ExecStart=/opt/donino-panel/current/.venv/bin/python -m ops.backup create
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/backups/donino /etc/donino
""",
        )
        self.managed_write(
            "/etc/systemd/system/donino-backup.timer",
            """[Unit]
Description=Daily encrypted Donino backup
[Timer]
OnCalendar=daily
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
""",
        )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "donino-backup.timer"])

    def app_cli(self, *arguments, release=None):
        release = release or CURRENT
        return run(
            [
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--uid=donino",
                "--property=EnvironmentFile=/etc/donino/panel.env",
                "--working-directory=" + str(release),
                str(release / ".venv/bin/python"),
                "-m",
                "app.cli",
                *arguments,
            ],
            capture=True,
            code=4,
        )

    def packages(self):
        new_unbound = bool(self.state.get("dns")) and shutil.which("unbound") is None
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
                "nginx",
                "postgresql",
                "postgresql-client",
                "certbot",
                *(["libnginx-mod-stream"] if self.state.get("smart_dns") else []),
                *(["unbound", "dns-root-data"] if self.state.get("dns") else []),
            ],
            env=env,
            code=3,
        )
        run(["systemctl", "start", "dbus"])
        if new_unbound:
            # Only the default service from the package we just introduced.
            # Existing resolvers retain their configuration and service state.
            run(["systemctl", "disable", "--now", "unbound"])
        run(["systemctl", "enable", "--now", "postgresql"])
        if not shutil.which("runuser"):
            raise InstallError("runuser is required", 3)
        if not any(Path("/usr/bin").glob("python3*")):
            raise InstallError("Python installation failed", 3)
        if not self.state.get("service_user"):
            try:
                pwd.getpwnam("donino")
            except KeyError:
                run(
                    [
                        "useradd",
                        "--system",
                        "--home-dir",
                        str(DATA),
                        "--shell",
                        "/usr/sbin/nologin",
                        "donino",
                    ]
                )
            self.state["service_user"] = "donino"
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        user = pwd.getpwnam("donino")
        os.chown(DATA, user.pw_uid, user.pw_gid)
        os.chmod(DATA, 0o700)
        CONFIG.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.checkpoint("packages")

    def code(self):
        manifest = verify_manifest(
            SOURCE,
            expected=self.args.source_sha256,
            development=self.args.development_source,
        )
        files, checksum = source_inventory(SOURCE)
        for directory in (
            Path("/opt/donino-panel"),
            Path("/opt/donino-panel/releases"),
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(directory, 0o755)
        release = Path("/opt/donino-panel/releases") / checksum[:20]
        release.mkdir(parents=True, exist_ok=True, mode=0o755)
        for path, relative in files:
            destination = release / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            for parent in (destination.parent, *destination.parent.parents):
                if parent == release.parent:
                    break
                os.chmod(parent, 0o755)
            content = path.read_bytes()
            if destination.exists() and destination.read_bytes() != content:
                raise InstallError(
                    "Immutable release directory was modified; refusing overwrite", 3
                )
            if not destination.exists():
                atomic_write(destination, content, 0o644)
        if not (release / ".venv/bin/python").exists():
            run([sys.executable, "-m", "venv", str(release / ".venv")], code=3)
        run(
            [
                str(release / ".venv/bin/python"),
                "-m",
                "pip",
                "install",
                "-r",
                str(release / "requirements.txt"),
                "-r",
                str(release / "requirements-postgres.txt"),
            ],
            code=3,
        )
        # Keep the previous release until config, migration and health succeed.
        self.state["candidate"] = str(release)
        self.state["source_sha256"] = checksum
        atomic_write(
            release / "release-manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            0o644,
        )
        self.checkpoint("code-ready")
        return release

    def scheme(self):
        return "http" if self.args.tls == "none" else "https"

    def environment(self, domain):
        path = CONFIG / "panel.env"
        if path.exists():
            values = read_env(path)
            if values.get("DONINO_PUBLIC_URL") != self.scheme() + "://" + domain:
                raise InstallError(
                    "Changing an existing domain requires a separate certificate/config migration",
                    5,
                )
            if "DONINO_PROXY_KEY" not in values:
                values["DONINO_PROXY_KEY"] = secrets.token_urlsafe(40)
                values["DONINO_PKI_DIR"] = str(DATA / "pki")
                atomic_write(
                    path,
                    "".join(key + "=" + value + "\n" for key, value in values.items()),
                )
            self.smart_environment(values)
            return values
        password = secrets.token_urlsafe(36)
        bootstrap = secrets.token_urlsafe(40)
        values = {
            "DONINO_DB": str(DATA / "donino.db"),
            "DONINO_DATABASE_URL": "postgresql://donino:"
            + password
            + "@127.0.0.1:5432/donino",
            "DONINO_KEY_FILE": str(DATA / "master.key"),
            "DONINO_PKI_DIR": str(DATA / "pki"),
            "DONINO_PROXY_KEY": secrets.token_urlsafe(40),
            "DONINO_PUBLIC_URL": self.scheme() + "://" + domain,
            "DONINO_SECURE_COOKIE": "false" if self.args.tls == "none" else "true",
            "DONINO_BOOTSTRAP_TOKEN_HASH": hashlib.sha256(
                bootstrap.encode()
            ).hexdigest(),
            "DONINO_BOOTSTRAP_EXPIRES": str(int(time.time()) + 3600),
        }
        self.smart_environment(values)
        atomic_write(
            path, "".join(key + "=" + value + "\n" for key, value in values.items())
        )
        atomic_write(
            STATE.parent / "bootstrap-access.txt",
            "One-use setup link (expires in one hour):\n"
            + self.scheme()
            + "://"
            + domain
            + "/#setup="
            + bootstrap
            + "\n",
        )
        self.checkpoint("environment")
        return values

    def smart_environment(self, values):
        if self.state.get("tunnel_monitor"):
            values["DONINO_TUNNEL_MONITOR"] = "1"
        elif self.args.without_tunnel_monitor:
            values["DONINO_TUNNEL_MONITOR"] = "0"
        if self.state.get("smart_dns"):
            values.update(
                DONINO_SMART_DNS="1",
                DONINO_SMART_DNS_IPS=",".join(self.state["smart_dns"]["addresses"]),
            )
        if (
            self.state.get("smart_dns")
            or self.state.get("tunnel_monitor")
            or self.args.without_tunnel_monitor
        ):
            atomic_write(
                CONFIG / "panel.env",
                "".join(key + "=" + value + "\n" for key, value in values.items()),
            )

    def database(self, values):
        from urllib.parse import urlsplit

        password = urlsplit(
            values["DONINO_DATABASE_URL"].replace(
                "postgresql+psycopg://", "postgresql://"
            )
        ).password
        exists = run(
            [
                "runuser",
                "-u",
                "postgres",
                "--",
                "psql",
                "-At",
                "-c",
                "SELECT 1 FROM pg_roles WHERE rolname='donino'",
            ],
            capture=True,
            code=4,
        ).strip()
        if exists:
            # Never reset or adopt a role with a different password.
            env = dict(os.environ, PGPASSWORD=password)
            run(
                [
                    "psql",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "donino",
                    "-d",
                    "postgres",
                    "-c",
                    "SELECT 1",
                ],
                capture=True,
                env=env,
                code=4,
            )
        else:
            if not password or any(
                c
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                for c in password
            ):
                raise InstallError("Unexpected database password format", 4)
            run(
                ["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1"],
                input="CREATE ROLE donino LOGIN PASSWORD '" + password + "';\n",
                capture=True,
                code=4,
            )
        database_exists = run(
            [
                "runuser",
                "-u",
                "postgres",
                "--",
                "psql",
                "-At",
                "-c",
                "SELECT 1 FROM pg_database WHERE datname='donino'",
            ],
            capture=True,
            code=4,
        ).strip()
        if not database_exists:
            run(
                [
                    "runuser",
                    "-u",
                    "postgres",
                    "--",
                    "createdb",
                    "--owner=donino",
                    "donino",
                ],
                code=4,
            )
        self.checkpoint("database")

    def activate(self, release):
        previous = str(CURRENT.resolve()) if CURRENT.is_symlink() else None
        pending = CURRENT.with_name(".current-next")
        pending.unlink(missing_ok=True)
        pending.symlink_to(release, target_is_directory=True)
        os.replace(pending, CURRENT)
        self.state["previous_release"] = previous
        self.checkpoint("candidate-selected")

    def proxy(self, domain, *, tls, plain=False):
        snippets = Path("/etc/nginx/snippets")
        snippets.mkdir(exist_ok=True)
        values = read_env(CONFIG / "panel.env")
        proxy_key = values.get("DONINO_PROXY_KEY", "")
        if len(proxy_key) < 32 or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for c in proxy_key
        ):
            raise InstallError("A valid private proxy authentication key is required")
        self.managed_write(
            snippets / "donino-proxy.conf",
            PROXY + "proxy_set_header X-Donino-Proxy-Key " + proxy_key + ";\n"
            "proxy_set_header X-Donino-Client-Verify $ssl_client_verify;\n"
            "proxy_set_header X-Donino-Client-Cert $ssl_client_escaped_cert;\n",
            0o600,
        )
        path = Path("/etc/nginx/conf.d/donino-panel.conf")
        smart = bool(tls and self.state.get("smart_dns"))
        targets = (path, smart_front.FRONT) if smart else (path,)
        previous = {p: p.read_bytes() if p.exists() else None for p in targets}
        inventory = dict(self.state.get("managed_files", {}))
        try:
            if smart:
                self.managed_write(
                    smart_front.FRONT,
                    smart_front.config(domain, ipv6=self.state.get("ipv6", True)),
                )
            self.managed_write(
                path,
                nginx_config(
                    domain,
                    tls=tls,
                    ipv6=self.state.get("ipv6", True),
                    smart=smart,
                    plain=plain,
                ),
                0o644,
            )
            run(["nginx", "-t"], capture=True)
            run(["systemctl", "enable", "--now", "nginx"])
            run(["systemctl", "reload", "nginx"])
        except BaseException:
            for target, content in previous.items():
                if content is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_write(target, content, 0o644)
            self.state["managed_files"] = inventory
            raise

    def certificate(self, domain):
        if self.args.tls == "none":
            self.proxy(domain, tls=False, plain=True)
            self.checkpoint("tls")
            return
        if self.args.tls == "existing":
            source_cert, source_key = self.args.cert_file, self.args.key_file
        else:
            webroot = Path("/var/lib/donino-acme")
            webroot.mkdir(parents=True, exist_ok=True, mode=0o755)
            # Do not downgrade an existing TLS vhost during reinstallation.
            if not (CONFIG / "tls/panel.crt").exists():
                self.proxy(domain, tls=False)
            command = [
                "certbot",
                "certonly",
                "--webroot",
                "--webroot-path",
                str(webroot),
                "--non-interactive",
                "--agree-tos",
                "--keep-until-expiring",
                "--cert-name",
                "donino-panel",
                "-d",
                domain,
            ]
            command += (
                ["--email", self.args.email]
                if self.args.email
                else ["--register-unsafely-without-email"]
            )
            if self.args.acme_staging:
                command.append("--staging")
            run(command, code=5)
            source_cert, source_key = (
                Path("/etc/letsencrypt/live/donino-panel/fullchain.pem"),
                Path("/etc/letsencrypt/live/donino-panel/privkey.pem"),
            )
        install_certificate(
            domain, source_cert, source_key, CONFIG / "tls", ca_file=self.args.ca_file
        )
        self.proxy(domain, tls=True)
        if self.args.tls == "acme":
            hooks = Path("/etc/letsencrypt/renewal-hooks/deploy")
            hooks.mkdir(parents=True, exist_ok=True, mode=0o755)
            self.managed_write(
                hooks / "donino-panel",
                "#!/bin/sh\nset -eu\ncd /opt/donino-panel/current\nexec /opt/donino-panel/current/.venv/bin/python -m ops.install renew-certificate\n",
                0o755,
            )
            run(["systemctl", "enable", "--now", "certbot.timer"])
        self.checkpoint("tls")

    def services(self, release):
        template = (SOURCE / "deploy/donino-panel.service").read_text()
        template = template.replace(
            "WorkingDirectory=/opt/donino-panel",
            "WorkingDirectory=/opt/donino-panel/current",
        ).replace(
            "ExecStart=/opt/donino-panel/.venv",
            "ExecStart=/opt/donino-panel/current/.venv",
        )
        self.managed_write("/etc/systemd/system/donino-panel.service", template)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "stop", "donino-panel"])
        if Path("/etc/systemd/system/donino-dns.service").exists():
            run(["systemctl", "stop", "donino-dns"])
        if smart_front.UNIT.exists():
            run(["systemctl", "stop", "donino-smart-gateway"])
        if monitor_ops.UNIT.exists():
            run(["systemctl", "stop", "donino-tunnel-monitor"])
        self.app_cli("migrate", release=release)
        if self.args.without_tunnel_monitor:
            self.app_cli("tunnel-monitor-disable", release=release)
        self.activate(release)
        run(["systemctl", "enable", "--now", "donino-panel"])
        run(["systemctl", "restart", "donino-panel"])
        if self.state.get("dns"):
            self.dns_services()
        if self.state.get("smart_dns"):
            self.smart_service()
        if self.state.get("tunnel_monitor"):
            self.monitor_service()
        elif monitor_ops.UNIT.exists():
            run(["systemctl", "disable", "donino-tunnel-monitor"])
        self.checkpoint("services")

    def monitor_service(self):
        self.managed_write(
            monitor_ops.UNIT,
            (SOURCE / "deploy/donino-tunnel-monitor.service").read_text(),
        )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "donino-tunnel-monitor"])
        run(["systemctl", "restart", "donino-tunnel-monitor"])
        run(
            [
                str(CURRENT / ".venv/bin/python"),
                "-c",
                """import os,time
from ops.common import read_env
os.environ.update(read_env('/etc/donino/panel.env'))
from app.db import database
from app.tunnel_monitor import ready
for attempt in range(60):
    with database() as db:
        ok=ready(db)
    if ok:
        break
    if attempt==59:
        raise RuntimeError('Tunnel monitor did not become ready')
    time.sleep(0.5)
""",
            ],
            cwd=CURRENT,
            capture=True,
        )

    def smart_service(self):
        self.managed_write(
            smart_front.UNIT,
            (SOURCE / "deploy/donino-smart-gateway.service").read_text(),
        )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "donino-smart-gateway"])
        run(["systemctl", "restart", "donino-smart-gateway"])
        run(["systemctl", "is-active", "--quiet", "donino-smart-gateway"])
        run(
            [
                str(CURRENT / ".venv/bin/python"),
                "-c",
                """import os,time
from ops.common import read_env
os.environ.update(read_env('/etc/donino/panel.env'))
from app.db import database
from app.smart_dns import gateway_ready
for attempt in range(60):
    with database() as db:
        ready=gateway_ready(db)
    if ready:
        break
    if attempt==59:
        raise RuntimeError('Smart DNS gateway did not become ready')
    time.sleep(0.5)
""",
            ],
            cwd=CURRENT,
            capture=True,
        )

    def dns_services(self):
        settings = self.state["dns"]
        self.dns_certificate()
        values = read_env(CONFIG / "panel.env")
        values.update(
            {
                "DONINO_DNS_LISTEN": settings["listen"],
                "DONINO_DNS_PORT": str(settings["port"]),
                "DONINO_DOT_PORT": str(settings["dot_port"]),
            }
        )
        atomic_write(
            CONFIG / "panel.env",
            "".join(key + "=" + value + "\n" for key, value in values.items()),
        )
        self.managed_write(
            "/etc/unbound/donino.conf",
            (SOURCE / "deploy/unbound-donino.conf.example").read_text(),
        )
        run(["unbound-checkconf", "/etc/unbound/donino.conf"], capture=True)
        for unit in ("donino-unbound.service", "donino-dns.service"):
            self.managed_write(
                "/etc/systemd/system/" + unit, (SOURCE / "deploy" / unit).read_text()
            )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "donino-unbound", "donino-dns"])
        run(["systemctl", "restart", "donino-unbound", "donino-dns"])
        run(["systemctl", "is-active", "--quiet", "donino-unbound", "donino-dns"])
        self.dns_health()

    def dns_health(self):
        settings = self.state["dns"]
        host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(
            settings["listen"], settings["listen"]
        )
        run(
            [
                str(CURRENT / ".venv/bin/python"),
                "-c",
                """import socket,ssl,sys,time
import dns.message,dns.query
context=ssl.create_default_context(cafile=sys.argv[5] or None)
for attempt in range(20):
    try:
        result=dns.query.udp(dns.message.make_query('donino.health.','A'),'127.0.0.1',port=5335,timeout=1)
        assert result.answer and result.answer[0][0].address=='127.0.0.1'
        with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1):
            pass
        with socket.create_connection((sys.argv[1],int(sys.argv[3])),timeout=1) as raw:
            with context.wrap_socket(raw,server_hostname=sys.argv[4]):
                pass
        break
    except (OSError,dns.exception.DNSException,AssertionError):
        if attempt==19:
            raise RuntimeError('DNS resolver/gateway/TLS readiness check failed') from None
        time.sleep(0.2)
""",
                host,
                str(settings["port"]),
                str(settings["dot_port"]),
                self.state["domain"],
                str(self.args.ca_file or ""),
            ],
            capture=True,
        )

    def dns_certificate(self):
        # Never write as root through an application-owned directory. The
        # service user receives the already verified pair via a private pipe.
        material = {
            name: (CONFIG / "tls" / name).read_text()
            for name in ("panel.crt", "panel.key")
        }
        run(
            [
                "runuser",
                "-u",
                "donino",
                "--",
                str(CURRENT / ".venv/bin/python"),
                "-m",
                "agent.dns_tls",
                str(DATA / "dns-tls"),
            ],
            input=json.dumps(material),
            capture=True,
            cwd=CURRENT,
        )

    def health(self):
        for attempt in range(30):
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8000/readyz", timeout=2
                ) as response:
                    result = json.load(response)
                    if result.get("status") == "ok":
                        self.state["app_version"] = result["version"]
                        self.checkpoint("health")
                        return result
            except (OSError, ValueError):
                pass
            time.sleep(1)
        raise InstallError(
            "Control-plane health check failed; database/config must be restored together if migration changed schema",
            6,
        )

    def repair(self):
        if not CURRENT.is_symlink() or not self.state.get("domain"):
            raise InstallError(
                "No managed installation to repair; resume install first"
            )
        monitor_ops.options(self.args, self.state)
        if self.args.with_tunnel_monitor or self.args.without_tunnel_monitor:
            raise InstallError(
                "Change tunnel monitor opt-in with install/upgrade before repair"
            )
        validate_certificate(
            self.state["domain"],
            CONFIG / "tls/panel.crt",
            CONFIG / "tls/panel.key",
            ca_file=self.args.ca_file,
        )
        self.proxy(self.state["domain"], tls=True)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "donino-panel"])
        if self.state.get("dns"):
            self.dns_services()
        if self.state.get("smart_dns"):
            self.smart_service()
        if self.state.get("tunnel_monitor"):
            self.monitor_service()
        self.health()
        self.checkpoint("complete")

    def uninstall(self):
        managed = self.state.get("managed_files", {})
        if not managed:
            raise InstallError(
                "No managed file inventory; refusing to remove unknown files"
            )
        # Check every file before stopping services or removing anything.
        for name, expected in managed.items():
            path = Path(name)
            if (
                path.exists()
                and hashlib.sha256(path.read_bytes()).hexdigest() != expected
            ):
                raise InstallError(
                    "A managed file has local changes; preserve/reconcile it before uninstall"
                )
        for unit in (
            "donino-tunnel-monitor.service",
            "donino-smart-gateway.service",
            "donino-dns.service",
            "donino-unbound.service",
            "donino-panel.service",
            "donino-backup.timer",
        ):
            if Path("/etc/systemd/system", unit).exists():
                run(["systemctl", "disable", "--now", unit])
        for name in managed:
            Path(name).unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
        run(["nginx", "-t"], capture=True)
        run(["systemctl", "reload", "nginx"])
        self.checkpoint("uninstalled")
        print(
            "Donino services removed. Database, credentials, releases and backups were preserved."
        )

    def install(self):
        domain = self.args.domain or self.state.get("domain")
        if not domain:
            if not sys.stdin.isatty():
                raise InstallError(
                    "--domain is required for non-interactive installation"
                )
            domain = input("Panel domain: ").strip()
        report = inspect(
            domain,
            expected=self.args.expected_ip,
            existing=bool(self.state.get("domain")),
            allow_nginx=self.args.allow_existing_nginx,
        )
        if report["errors"]:
            raise InstallError("; ".join(report["errors"]))
        if not STATE.exists() and (
            Path("/etc/systemd/system/donino-panel.service").exists()
            or (CONFIG / "panel.env").exists()
            or (DATA.exists() and any(DATA.iterdir()))
        ):
            raise InstallError(
                "Existing manual Donino service detected; automatic adoption refused"
            )
        verify_manifest(
            SOURCE,
            expected=self.args.source_sha256,
            development=self.args.development_source,
        )
        settings = dns_options(self.args, self.state)
        smart = smart_front.options(self.args, self.state, settings)
        monitor = monitor_ops.options(self.args, self.state)
        if self.args.tls == "none":
            if (
                self.args.cert_file
                or self.args.key_file
                or self.args.ca_file
                or self.args.email
                or self.args.acme_staging
            ):
                raise InstallError(
                    "--tls none does not accept certificate, email or staging options",
                    5,
                )
            if smart or settings:
                raise InstallError(
                    "DNS and Smart DNS (DoH) require HTTPS; use --tls acme or existing",
                    5,
                )
        if self.state.get("domain") and self.state.get(
            "tls_mode", "acme"
        ) != self.args.tls:
            raise InstallError(
                "TLS mode cannot change on an existing installation; restore a backup on a fresh host instead",
                5,
            )
        if smart:
            inventory = self.state.get("managed_files", {})
            for target in (smart_front.FRONT, smart_front.PANEL, smart_front.UNIT):
                if (
                    target.exists()
                    and inventory.get(str(target))
                    != hashlib.sha256(target.read_bytes()).hexdigest()
                ):
                    raise InstallError(
                        "Refusing to overwrite unmanaged or modified Smart DNS configuration"
                    )
            smart_front.preflight(self.state)
        if settings:
            inventory = self.state.get("managed_files", {})
            for path in (
                "/etc/unbound/donino.conf",
                "/etc/systemd/system/donino-unbound.service",
                "/etc/systemd/system/donino-dns.service",
            ):
                target = Path(path)
                if (
                    target.exists()
                    and inventory.get(path)
                    != hashlib.sha256(target.read_bytes()).hexdigest()
                ):
                    raise InstallError(
                        "Refusing to overwrite unmanaged or modified DNS configuration"
                    )
            if (
                settings != self.state.get("dns")
                or "/etc/systemd/system/donino-dns.service" not in inventory
            ):
                available_dns_ports(
                    settings,
                    include_upstream="/etc/systemd/system/donino-unbound.service"
                    not in inventory,
                )
        if self.args.tls == "existing":
            if not self.args.cert_file or not self.args.key_file:
                raise InstallError(
                    "Existing TLS requires --cert-file and --key-file", 5
                )
            if shutil.which("openssl"):
                validate_certificate(
                    report["domain"],
                    self.args.cert_file,
                    self.args.key_file,
                    ca_file=self.args.ca_file,
                )
        STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state["domain"] = report["domain"]
        self.state["tls_mode"] = self.args.tls
        self.state["ipv6"] = report["ipv6"]
        if settings:
            self.state["dns"] = settings
        if smart:
            self.state["smart_dns"] = smart
        self.state["tunnel_monitor"] = monitor
        self.checkpoint("preflight")
        self.packages()
        release = self.code()
        values = self.environment(report["domain"])
        self.database(values)
        if CURRENT.is_symlink():
            backup = self.backup(release=release)
            self.state["pre_upgrade_backup"] = str(backup)
        self.app_cli("pki-init", release=release)
        self.certificate(report["domain"])
        self.services(release)
        self.health()
        self.backup()
        self.backup_timer()
        self.checkpoint("complete")
        print("Donino installed: " + self.scheme() + "://" + report["domain"])
        if self.args.tls == "none":
            print(
                "WARNING: plain HTTP. The owner password and session cookies are not encrypted on the network. Use --tls acme for any real deployment."
            )
        print(
            "Initial one-use access is in /var/lib/donino-installer/bootstrap-access.txt (if no owner exists)."
        )
        print(
            "Preserve /etc/donino/backup.key separately outside this host; encrypted backups are in /var/backups/donino/."
        )


def arguments(argv=None):
    parser = argparse.ArgumentParser(
        description="Donino native installer — development preview"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="install",
        choices=[
            "plan",
            "install",
            "upgrade",
            "doctor",
            "backup",
            "restore",
            "repair",
            "uninstall",
            "bootstrap",
            "renew-certificate",
        ],
    )
    parser.add_argument("--domain")
    parser.add_argument("--role", choices=["control", "smart-exit"], default="control")
    parser.add_argument(
        "--exit-allow-domain",
        action="append",
        default=[],
        help="Smart exit allowed domain suffix; repeat",
    )
    parser.add_argument("--exit-listen", help="Smart exit bind IP (default: 0.0.0.0)")
    parser.add_argument(
        "--exit-port", type=int, help="Smart exit TLS port (default: 9445)"
    )
    parser.add_argument("--archive", type=Path, help="Backup output or restore input")
    parser.add_argument(
        "--backup-key-file", type=Path, default=Path("/etc/donino/backup.key")
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply restoration into an empty database; otherwise inspect only",
    )
    parser.add_argument(
        "--source-sha256",
        help="Expected source inventory digest from the release manifest",
    )
    parser.add_argument(
        "--development-source",
        action="store_true",
        help="Explicitly permit a local source tree without a release manifest",
    )
    parser.add_argument("--expected-ip", action="append", default=[])
    parser.add_argument("--email")
    parser.add_argument("--allow-existing-nginx", action="store_true")
    parser.add_argument(
        "--tls",
        choices=["acme", "existing", "none"],
        help="acme: Let's Encrypt; existing: your certificate; none: plain HTTP without a certificate (cleartext)",
    )
    parser.add_argument("--cert-file", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--acme-staging", action="store_true")
    monitor_flags = parser.add_mutually_exclusive_group()
    monitor_flags.add_argument(
        "--with-tunnel-monitor",
        action="store_true",
        help="Enable real-client tunnel renewal after bridge/verifier provisioning",
    )
    monitor_flags.add_argument(
        "--without-tunnel-monitor",
        action="store_true",
        help="Disable the optional monitor and future automatic publication",
    )
    parser.add_argument(
        "--with-dns",
        action="store_true",
        help="Install optional same-host Unbound and DNS/DoT gateway",
    )
    parser.add_argument("--dns-listen", help="DNS/DoT listen IP (default: loopback)")
    parser.add_argument(
        "--dns-port", type=int, help="UDP/TCP gateway port (default: 5353)"
    )
    parser.add_argument("--dot-port", type=int, help="DoT gateway port (default: 8530)")
    parser.add_argument(
        "--with-smart-dns",
        action="store_true",
        help="Opt in to same-IP HTTPS SNI routing; requires --with-dns",
    )
    parser.add_argument(
        "--smart-dns-ip",
        action="append",
        default=[],
        help="Advertised gateway IP, repeat for IPv4/IPv6",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    try:
        if args.role == "smart-exit":
            from .exit_install import main as exit_main

            return exit_main(args)
        try:
            saved = json.loads(STATE.read_text()) if STATE.exists() else {}
        except (OSError, ValueError):
            saved = {}
        args.tls = args.tls or saved.get("tls_mode", "acme")
        if (
            args.exit_allow_domain
            or args.exit_listen is not None
            or args.exit_port is not None
        ):
            raise InstallError("Exit options require --role smart-exit")
        if args.command == "plan":
            if not args.domain:
                raise InstallError("plan requires --domain")
            report = inspect(
                args.domain,
                expected=args.expected_ip,
                allow_nginx=args.allow_existing_nginx,
            )
            report["dns"] = dns_options(
                args, json.loads(STATE.read_text()) if STATE.exists() else {}
            )
            report["smart_dns"] = smart_front.options(
                args,
                json.loads(STATE.read_text()) if STATE.exists() else {},
                report["dns"],
            )
            report["tunnel_monitor"] = monitor_ops.options(
                args, json.loads(STATE.read_text()) if STATE.exists() else {}
            )
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 2 if report["errors"] else 0
        if args.command == "doctor":
            state = json.loads(STATE.read_text()) if STATE.exists() else {}
            report = {
                "installed": bool(state),
                "stage": state.get("last_stage"),
                "domain": state.get("domain"),
                "app_version": state.get("app_version"),
                "installation_complete": state.get("last_stage") == "complete",
                "dns": state.get("dns"),
                "smart_dns": state.get("smart_dns"),
                "tunnel_monitor": state.get("tunnel_monitor", False),
            }
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8000/readyz", timeout=3
                ) as response:
                    report["api"] = json.load(response)
            except (OSError, ValueError):
                report["api"] = "unavailable"
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return (
                0
                if report["installation_complete"] and report["api"] != "unavailable"
                else 6
            )
        if os.geteuid() != 0:
            raise InstallError("Run installation/renewal as root")
        STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(STATE.parent / "install.lock", "a") as lock:
            os.chmod(STATE.parent / "install.lock", 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstallError("Another Donino installer is running", 7) from exc
            installer = Installer(args)
            if args.command == "backup":
                installer.backup(destination=args.archive)
            elif args.command == "restore":
                if not args.archive:
                    raise InstallError("restore requires --archive")
                command = [
                    str(CURRENT / ".venv/bin/python"),
                    "-m",
                    "ops.backup",
                    "restore",
                    str(args.archive),
                    "--key-file",
                    str(args.backup_key_file),
                ]
                if args.apply:
                    command.append("--apply")
                run(command, cwd=CURRENT)
            elif args.command == "repair":
                installer.repair()
            elif args.command == "uninstall":
                installer.uninstall()
            elif args.command == "bootstrap":
                result = json.loads(installer.app_cli("bootstrap-status"))
                if result["administrators"]:
                    raise InstallError(
                        "First-owner bootstrap is closed; use the local admin CLI for recovery"
                    )
                values = read_env(CONFIG / "panel.env")
                token = secrets.token_urlsafe(40)
                values["DONINO_BOOTSTRAP_TOKEN_HASH"] = hashlib.sha256(
                    token.encode()
                ).hexdigest()
                values["DONINO_BOOTSTRAP_EXPIRES"] = str(int(time.time()) + 3600)
                atomic_write(
                    CONFIG / "panel.env",
                    "".join(key + "=" + value + "\n" for key, value in values.items()),
                )
                atomic_write(
                    STATE.parent / "bootstrap-access.txt",
                    "One-use setup link (expires in one hour):\n"
                    + values["DONINO_PUBLIC_URL"]
                    + "/#setup="
                    + token
                    + "\n",
                )
                run(["systemctl", "restart", "donino-panel"])
                print(
                    "New one-use link written to /var/lib/donino-installer/bootstrap-access.txt"
                )
            elif args.command == "renew-certificate":
                lineage = os.environ.get(
                    "RENEWED_LINEAGE", "/etc/letsencrypt/live/donino-panel"
                )
                if Path(lineage).name != "donino-panel":
                    return 0
                if not installer.state.get("domain"):
                    raise InstallError("No installed domain for renewal", 5)
                install_certificate(
                    installer.state["domain"],
                    Path(lineage) / "fullchain.pem",
                    Path(lineage) / "privkey.pem",
                    CONFIG / "tls",
                    check=lambda: run(["nginx", "-t"], capture=True),
                    reload=lambda: run(["systemctl", "reload", "nginx"]),
                )
                if installer.state.get("dns"):
                    installer.dns_certificate()
                    run(["systemctl", "restart", "donino-dns"])
                    installer.dns_health()
            else:
                installer.install()
        return 0
    except InstallError as exc:
        print("Donino: " + str(exc), file=sys.stderr)
        return exc.code
    except (OSError, ValueError) as exc:
        print(
            "Donino: operation failed ("
            + type(exc).__name__
            + "); the last completed stage is in /var/lib/donino-installer/state.json",
            file=sys.stderr,
        )
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
