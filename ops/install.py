"""Idempotent native control-plane installer. No third-party imports at bootstrap."""

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import secrets
import shutil
import sys
import time
import urllib.request
from pathlib import Path

from .common import InstallError, atomic_write, read_env, run, save_state
from .manifest import source_inventory, verify_manifest
from .preflight import domain_name, inspect
from .tls import install_certificate, validate_certificate

SOURCE = Path(__file__).resolve().parent.parent
STATE = Path("/var/lib/donino-installer/state.json")
CONFIG = Path("/etc/donino")
DATA = Path("/var/lib/donino-panel")
CURRENT = Path("/opt/donino-panel/current")


def nginx_config(domain, *, tls=False, ipv6=True):
    domain = domain_name(domain)
    common = """
    client_max_body_size 2m;
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
    if not tls:
        return http
    return (
        http
        + f"""server {{
    listen 443 ssl;
    {"listen [::]:443 ssl;" if ipv6 else ""}
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
            ],
            env=env,
            code=3,
        )
        run(["systemctl", "start", "dbus"])
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

    def environment(self, domain):
        path = CONFIG / "panel.env"
        if path.exists():
            values = read_env(path)
            if values.get("DONINO_PUBLIC_URL") != "https://" + domain:
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
            "DONINO_PUBLIC_URL": "https://" + domain,
            "DONINO_SECURE_COOKIE": "true",
            "DONINO_BOOTSTRAP_TOKEN_HASH": hashlib.sha256(
                bootstrap.encode()
            ).hexdigest(),
            "DONINO_BOOTSTRAP_EXPIRES": str(int(time.time()) + 3600),
        }
        atomic_write(
            path, "".join(key + "=" + value + "\n" for key, value in values.items())
        )
        atomic_write(
            STATE.parent / "bootstrap-access.txt",
            "One-use setup link (expires in one hour):\nhttps://"
            + domain
            + "/#setup="
            + bootstrap
            + "\n",
        )
        self.checkpoint("environment")
        return values

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

    def proxy(self, domain, *, tls):
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
        previous = path.read_bytes() if path.exists() else None
        try:
            self.managed_write(
                path,
                nginx_config(domain, tls=tls, ipv6=self.state.get("ipv6", True)),
                0o644,
            )
            run(["nginx", "-t"], capture=True)
            run(["systemctl", "enable", "--now", "nginx"])
            run(["systemctl", "reload", "nginx"])
        except BaseException:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, previous, 0o644)
            raise

    def certificate(self, domain):
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
        self.app_cli("migrate", release=release)
        self.activate(release)
        run(["systemctl", "enable", "--now", "donino-panel"])
        run(["systemctl", "restart", "donino-panel"])
        self.checkpoint("services")

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
        validate_certificate(
            self.state["domain"],
            CONFIG / "tls/panel.crt",
            CONFIG / "tls/panel.key",
            ca_file=self.args.ca_file,
        )
        self.proxy(self.state["domain"], tls=True)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "donino-panel"])
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
        for unit in ("donino-panel.service", "donino-backup.timer"):
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
        self.state["ipv6"] = report["ipv6"]
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
        print("Donino installed: https://" + report["domain"])
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
    parser.add_argument("--tls", choices=["acme", "existing"], default="acme")
    parser.add_argument("--cert-file", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--acme-staging", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    try:
        if args.command == "plan":
            if not args.domain:
                raise InstallError("plan requires --domain")
            report = inspect(
                args.domain,
                expected=args.expected_ip,
                allow_nginx=args.allow_existing_nginx,
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
