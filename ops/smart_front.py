"""Optional same-IP TLS passthrough frontend; no global NGINX config edits."""

import ipaddress
import re
import shutil
import socket
from pathlib import Path

from .common import InstallError, run
from .preflight import domain_name

FRONT = Path("/etc/nginx/modules-enabled/99-donino-smart-front.conf")
PANEL = Path("/etc/nginx/conf.d/donino-panel.conf")
UNIT = Path("/etc/systemd/system/donino-smart-gateway.service")


def options(args, state, dns):
    previous = state.get("smart_dns")
    if not (args.with_smart_dns or previous):
        if args.smart_dns_ip:
            raise InstallError("--smart-dns-ip requires --with-smart-dns")
        return None
    if not dns:
        raise InstallError("Smart DNS requires --with-dns")
    raw = args.smart_dns_ip or (previous or {}).get("addresses", [])
    try:
        addresses = sorted({str(ipaddress.ip_address(v)) for v in raw})
        if not 1 <= len(addresses) <= 8 or any(
            ipaddress.ip_address(v).is_unspecified
            or ipaddress.ip_address(v).is_multicast
            or ipaddress.ip_address(v).is_link_local
            or "%" in v
            for v in addresses
        ):
            raise ValueError
    except ValueError as exc:
        raise InstallError(
            "Supply 1–8 explicit usable --smart-dns-ip addresses"
        ) from exc
    return {"addresses": addresses}


def config(domain, *, ipv6=True):
    domain = domain_name(domain)
    return f"""# Managed by Donino. TLS passes unchanged to the selected backend.
stream {{
    map $ssl_preread_server_name $donino_smart_backend {{
        {domain} 127.0.0.1:8443;
        "" 127.0.0.1:8443;
        default 127.0.0.1:8444;
    }}
    server {{
        listen 443;
        {"listen [::]:443;" if ipv6 else ""}
        ssl_preread on;
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 90s;
        proxy_pass $donino_smart_backend;
    }}
}}
"""


def preflight(state):
    """Reject conflicting/custom listeners before interrupting a service."""
    inventory = state.get("managed_files", {})
    if not state.get("smart_dns"):
        for port in (8443, 8444):
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError as exc:
                    raise InstallError(
                        f"Smart DNS requires free loopback TCP/{port}"
                    ) from exc
    main = Path("/etc/nginx/nginx.conf")
    if not main.exists():
        return  # A clean Debian/Ubuntu package supplies this top-level include.
    if not re.search(
        r"include\s+/etc/nginx/modules-enabled/\*\.conf\s*;", main.read_text()
    ):
        raise InstallError(
            "Smart DNS requires the packaged NGINX modules-enabled include"
        )
    if not shutil.which("nginx"):
        raise InstallError("Existing NGINX configuration cannot be inspected")
    output = run(["nginx", "-T"], capture=True)
    parts = re.split(r"# configuration file ([^\n]+):\n", output)
    for name, content in zip(parts[1::2], parts[2::2]):
        if name in (str(FRONT), str(PANEL)) and name in inventory:
            continue
        content = re.sub(r"#[^\n]*", "", content)
        if re.search(r"\bstream\s*\{", content) or re.search(
            r"\blisten\s+(?:[^\s;]*:)?443(?:\s|;)", content
        ):
            raise InstallError(
                "Smart DNS cannot adopt unmanaged stream or TCP/443 listeners"
            )
