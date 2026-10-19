import ipaddress
import os
import platform
import re
import shutil
import socket
import sys
import urllib.request
from pathlib import Path

from .common import InstallError


def domain_name(value, *, allow_ip=False):
    if allow_ip:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            if address.version != 4:
                raise InstallError(
                    "HTTP literal address must be IPv4; a domain may have AAAA"
                )
            return str(address)
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InstallError("Invalid domain name") from exc
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise InstallError(
            "A domain without scheme, port, wildcard or path is required"
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise InstallError("Use a domain name for automatic TLS, not an IP address")


def os_release(path=Path("/etc/os-release")):
    fields = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip('"')
    return fields


def free_port(port, host="0.0.0.0"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def local_addresses():
    values = {"127.0.0.1", "::1"}
    try:
        values.update(
            row[4][0] for row in socket.getaddrinfo(socket.gethostname(), None)
        )
    except OSError:
        pass
    return values


def resolve_and_check(domain, expected=()):
    try:
        actual = {
            row[4][0] for row in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
        }
    except OSError as exc:
        raise InstallError(
            "Domain DNS could not be resolved; configure A/AAAA first", 5
        ) from exc
    allowed = {str(ipaddress.ip_address(value)) for value in expected}
    allowed.update(local_addresses())
    if not expected:
        try:
            with urllib.request.urlopen(
                "https://api.ipify.org", timeout=10
            ) as response:
                allowed.add(
                    str(ipaddress.ip_address(response.read(80).decode().strip()))
                )
        except (OSError, ValueError):
            pass
    unexpected = actual - allowed
    if not actual or unexpected:
        raise InstallError(
            "Domain A/AAAA does not match the detected/explicit server addresses; fix DNS or supply every intended --expected-ip",
            5,
        )
    return sorted(actual)


def inspect(
    domain,
    *,
    expected=(),
    existing=False,
    allow_nginx=False,
    network=True,
    ports=(80, 443),
    plain=False,
):
    domain = domain_name(domain, allow_ip=plain)
    if plain and ports == (80, 443):
        ports = (80,)
    release = os_release()
    errors = []
    if (release.get("ID"), release.get("VERSION_ID")) not in {
        ("ubuntu", "24.04"),
        ("debian", "12"),
    }:
        errors.append("Supported target OS: Ubuntu 24.04 or Debian 12")
    if platform.machine() not in {"x86_64", "amd64"}:
        errors.append(
            "Only amd64 artifacts have been selected; other architectures are not supported yet"
        )
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer is required")
    if os.geteuid() != 0:
        errors.append("Installation requires root")
    if not Path("/run/systemd/system").is_dir():
        errors.append(
            "A running systemd host is required; a plain container is not a VM acceptance environment"
        )
    if shutil.disk_usage("/").free < 1_073_741_824:
        errors.append("At least 1 GiB free disk is required")
    ipv6 = socket.has_ipv6 and free_port(0, "::")
    for port in ports:
        if (not free_port(port) or (ipv6 and not free_port(port, "::"))) and not (
            existing or allow_nginx
        ):
            errors.append(
                f"TCP/{port} is occupied; explicit --allow-existing-nginx is required for adding a vhost to an existing NGINX"
            )
    addresses = []
    if network:
        try:
            addresses = resolve_and_check(
                domain,
                expected
                or ([domain] if plain and re.fullmatch(r"[0-9.]+", domain) else ()),
            )
            if not ipv6 and any(":" in address for address in addresses):
                errors.append("Domain has AAAA but this host cannot listen on IPv6")
        except InstallError as exc:
            errors.append(str(exc))
    return {
        "domain": domain,
        "os": release.get("ID"),
        "os_version": release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "ipv6": ipv6,
        "addresses": addresses,
        "errors": errors,
        "required_public_ports": [str(port) + "/tcp" for port in ports],
        "database": "postgresql",
        "tls": "none" if plain else "nginx+certbot",
    }
