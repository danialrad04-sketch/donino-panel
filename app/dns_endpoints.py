"""Public DNS connection metadata; configuration is not a readiness assertion."""

import ipaddress
import os
from urllib.parse import urlsplit


def connection_info(base):
    raw = os.environ.get(
        "DONINO_DNS_PUBLIC_IPS", os.environ.get("DONINO_DNS_LISTEN", "")
    )
    addresses = []
    for item in raw.split(","):
        try:
            address = ipaddress.ip_address(item.strip())
        except ValueError:
            continue
        if "%" in item:
            continue
        if not (
            address.is_unspecified or address.is_multicast or address.is_link_local
        ):
            addresses.append(str(address))
    configured = os.environ.get("DONINO_DNS_ENABLED", "") == "1"
    https = urlsplit(base).scheme == "https"
    return {
        "configured": configured,
        "addresses": sorted(set(addresses)),
        "port": int(os.environ.get("DONINO_DNS_PORT", "53")),
        "transports": ["udp", "tcp"] if configured else [],
        "dot_port": int(os.environ.get("DONINO_DOT_PORT") or 0)
        if configured and https
        else None,
        "doh_url": base.rstrip("/") + "/dns-query" if https else None,
        "access": "registered-source-ip",
        "same_host_only": True,
    }
