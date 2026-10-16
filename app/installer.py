"""Installer scaffold for Donino (phase 2, first slice).

What this slice does:
  preflight  read-only checks: OS, architecture, Python, ports, free disk, DNS.
  plan       prints what render would write, with no secrets.
  render     writes the panel env file, systemd unit and NGINX vhost under a root
             directory (default /), under a lock, with a resumable state file.

What it deliberately does NOT do yet: start or enable services, reload NGINX,
request certificates, change firewall rules. Those need a real VPS and are
tracked in docs/INSTALLER-SPEC.fa.md. Existing files with different content are
never overwritten silently: render exits 7 and asks for a manual decision.

Exit codes follow the spec: 0 success, 2 input or prerequisite error,
5 DNS/TLS problem, 7 lock held or manual decision required.
"""

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import sys
import time
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent
SUPPORTED_OS = {("ubuntu", "24.04"), ("debian", "12")}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$")
EXIT_OK, EXIT_INPUT, EXIT_DNS, EXIT_MANUAL = 0, 2, 5, 7


class InstallError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def validate_domain(domain):
    if not DOMAIN_RE.match(domain or ""):
        raise InstallError(EXIT_INPUT, "domain must be a bare hostname such as panel.example.com")
    return domain.lower()


def read_os_release(path="/etc/os-release"):
    values = {}
    try:
        for line in Path(path).read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def port_free(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def preflight(domain, expected_ip=None, root="/", allow_unsupported=False, min_free_mb=512):
    """Read-only checks. Returns a list of (level, name, detail) rows."""
    domain = validate_domain(domain)
    rows = []
    release = read_os_release(Path(root, "etc/os-release") if root != "/" else "/etc/os-release")
    os_key = (release.get("ID", ""), release.get("VERSION_ID", ""))
    if os_key in SUPPORTED_OS:
        rows.append(("OK", "os", " ".join(os_key)))
    elif allow_unsupported:
        rows.append(("WARN", "os", f"{os_key} is not in the tested set"))
    else:
        raise InstallError(EXIT_INPUT, f"unsupported OS {os_key}; tested: ubuntu 24.04, debian 12")

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        rows.append(("OK", "architecture", "amd64"))
    else:
        raise InstallError(EXIT_INPUT, f"architecture {machine} is not supported yet")

    if sys.version_info >= (3, 12):
        rows.append(("OK", "python", platform.python_version()))
    else:
        raise InstallError(EXIT_INPUT, "Python 3.12 or newer is required")

    if root == "/" and os.geteuid() != 0:
        raise InstallError(EXIT_INPUT, "run as root, or pass --root for a test directory")
    rows.append(("OK", "privileges", "root" if root == "/" else f"test root {root}"))

    for port in (80, 443):
        if port_free(port):
            rows.append(("OK", f"port {port}", "free"))
        else:
            rows.append(("WARN", f"port {port}", "in use; resolve before enabling NGINX"))

    free_mb = os.statvfs(root).f_bavail * os.statvfs(root).f_frsize // (1024 * 1024)
    if free_mb >= min_free_mb:
        rows.append(("OK", "disk", f"{free_mb} MB free"))
    else:
        raise InstallError(EXIT_INPUT, f"only {free_mb} MB free; need {min_free_mb} MB")

    try:
        _, _, addresses = socket.gethostbyname_ex(domain)
    except OSError:
        raise InstallError(EXIT_DNS, f"{domain} does not resolve; create the A record first")
    if expected_ip and expected_ip not in addresses:
        raise InstallError(EXIT_DNS, f"{domain} resolves to {addresses}, not {expected_ip}")
    rows.append(("OK", "dns", f"{domain} -> {', '.join(addresses)}"))
    return rows


def render_files(domain, root):
    """Return {relative path: (content, mode)} for the files this slice owns."""
    env = (
        "# Written by donino installer. Not loaded automatically outside systemd.\n"
        f"DONINO_DB=/var/lib/donino-panel/donino.db\n"
        f"DONINO_PUBLIC_URL=https://{domain}\n"
        "DONINO_SECURE_COOKIE=true\n"
    )
    unit = (PACKAGE / "deploy/donino-panel.service").read_text()
    nginx_template = (PACKAGE / "deploy/nginx.conf.example").read_text()
    if nginx_template.count("panel.example.com") < 2:
        raise InstallError(EXIT_INPUT, "nginx template placeholder not found; refusing to render")
    nginx = nginx_template.replace("panel.example.com", domain)
    return {
        "etc/donino/panel.env": (env, 0o600),
        "etc/systemd/system/donino-panel.service": (unit, 0o644),
        "etc/nginx/sites-available/donino-panel.conf": (nginx, 0o644),
    }


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Lock:
    def __init__(self, root):
        self.path = Path(root, "run/donino-install.lock")

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "w")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.close()
            raise InstallError(EXIT_MANUAL, "another installer run holds the lock")
        self.handle.write(str(os.getpid()))
        self.handle.flush()
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()
        return False


def render(domain, root="/"):
    domain = validate_domain(domain)
    root = Path(root)
    with Lock(root):
        files = render_files(domain, root)
        # Check everything first so a conflict leaves no partial changes behind.
        conflicts = []
        for relative, (content, _) in files.items():
            target = root / relative
            if target.exists() and digest(target.read_text()) != digest(content):
                conflicts.append(relative)
        if conflicts:
            raise InstallError(
                EXIT_MANUAL,
                "existing files differ and will not be overwritten: " + ", ".join(conflicts),
            )
        written, unchanged = [], []
        for relative, (content, mode) in files.items():
            target = root / relative
            if target.exists():
                unchanged.append(relative)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "w") as handle:
                handle.write(content)
            os.chmod(target, mode)
            written.append(relative)
        state_path = root / "var/lib/donino-installer/state.json"
        state = {}
        if state_path.exists():
            state = json.loads(state_path.read_text())
        state.setdefault("install_id", secrets.token_hex(8))
        state["domain"] = domain
        state["stages"] = {**state.get("stages", {}), "render": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2))
        return {"written": written, "unchanged": unchanged, "state": str(state_path)}


def plan(domain, root="/"):
    domain = validate_domain(domain)
    return {
        "domain": domain,
        "root": str(root),
        "files": sorted(render_files(domain, root)),
        "not_done_by_this_slice": [
            "start or enable systemd services",
            "reload NGINX or run nginx -t",
            "request TLS certificates",
            "change firewall rules",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Donino installer (scaffold)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "plan", "render"):
        item = sub.add_parser(name)
        item.add_argument("--domain", required=True)
        item.add_argument("--root", default="/")
        if name == "preflight":
            item.add_argument("--expected-ip")
            item.add_argument("--allow-unsupported", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            for level, name, detail in preflight(
                args.domain, args.expected_ip, args.root, args.allow_unsupported
            ):
                print(f"{level:4} {name}: {detail}")
            return EXIT_OK
        if args.command == "plan":
            print(json.dumps(plan(args.domain, args.root), indent=2, ensure_ascii=False))
            return EXIT_OK
        result = render(args.domain, args.root)
        print(json.dumps(result, indent=2))
        return EXIT_OK
    except InstallError as error:
        print(f"install stopped (exit {error.code}): {error}", file=sys.stderr)
        return error.code


if __name__ == "__main__":
    raise SystemExit(main())
