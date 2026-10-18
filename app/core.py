"""Independent Xray compiler and client profile serializers.

A "client" is one device credential. Its id is the Xray client email and the
counter key. The default device of every user uses the user id as its id and the
legacy user credential as its secret, so pre-0.3 configurations and counter
baselines stay valid after upgrade.
"""

import base64
import hashlib
import json
import time
from urllib.parse import urlencode, quote


# Transports per protocol. Old rows that predate the transport key keep the
# transport they had before: VLESS REALITY/TCP, VMess WS, Trojan TCP.
TRANSPORTS = {
    "vless": ("tcp", "ws", "grpc"),
    "vmess": ("ws", "grpc"),
    "trojan": ("tcp", "ws"),
}
DEFAULT_TRANSPORT = {"vless": "tcp", "vmess": "ws", "trojan": "tcp"}


def transport_of(protocol, settings):
    return settings.get("transport") or DEFAULT_TRANSPORT[protocol]


def is_reality(protocol, transport):
    return protocol == "vless" and transport == "tcp"


def eligible(user, now=None):
    now = time.time() if now is None else now
    return bool(
        user["enabled"]
        and (not user["expires"] or user["expires"] > now)
        and (not user["quota"] or user["used"] < user["quota"])
    )


def status(user):
    if not user["enabled"]:
        return "disabled"
    if user["expires"] and user["expires"] <= time.time():
        return "expired"
    if user["quota"] and user["used"] >= user["quota"]:
        return "limited"
    return "active"


def compile_config(inbounds, clients):
    """clients: dicts with id, secret and eligible (user and device both allowed)."""
    live = [c for c in clients if c["eligible"]]
    result = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}
        },
        "inbounds": [
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            ]
        },
    }
    for inbound in inbounds:
        if not inbound["enabled"]:
            continue
        s = json.loads(inbound["settings"])
        protocol = inbound["protocol"]
        transport = transport_of(protocol, s)
        clients = [
            {
                "email": c["id"],
                "level": 0,
                ("password" if protocol == "trojan" else "id"): c["secret"],
            }
            for c in live
        ]
        if is_reality(protocol, transport):
            for client in clients:
                client["flow"] = "xtls-rprx-vision"
            stream = {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": s["target"],
                    "serverNames": [s["sni"]],
                    "privateKey": s["private_key"],
                    "shortIds": [s["short_id"]],
                },
            }
        else:
            # Vision flow is REALITY/TCP only; WS and gRPC carry plain VLESS.
            tls = {
                "certificates": [
                    {"certificateFile": s["cert_file"], "keyFile": s["key_file"]}
                ]
            }
            stream = {"network": transport, "security": "tls", "tlsSettings": tls}
            if transport == "ws":
                stream["wsSettings"] = {"path": s["path"]}
            elif transport == "grpc":
                tls["alpn"] = ["h2"]
                stream["grpcSettings"] = {"serviceName": s["service_name"]}
        settings = {"clients": clients}
        if protocol == "vless":
            settings["decryption"] = "none"
        result["inbounds"].append(
            {
                "tag": inbound["id"],
                "listen": "0.0.0.0",
                "port": inbound["port"],
                "protocol": protocol,
                "settings": settings,
                "streamSettings": stream,
            }
        )
    return result


def revision(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def _transport_options(transport, s):
    """Client-side stream settings for TLS transports (URI query, Mihomo opts)."""
    if transport == "ws":
        return (
            {"type": "ws", "host": s["sni"], "path": s["path"]},
            {"ws-opts": {"path": s["path"], "headers": {"Host": s["sni"]}}},
        )
    if transport == "grpc":
        return (
            {"type": "grpc", "serviceName": s["service_name"], "mode": "gun"},
            {"grpc-opts": {"grpc-service-name": s["service_name"]}},
        )
    return {"type": "tcp"}, {}


def profiles(clients, inbounds):
    """clients: dicts with id, secret, device_name, eligible (only eligible are emitted)."""
    links, clash = [], []
    for inbound in inbounds:
        if not inbound["enabled"] or not inbound["node_enabled"]:
            continue
        s = json.loads(inbound["settings"])
        host = inbound["host"]
        address = f"[{host}]" if ":" in host else host
        port = inbound["port"]
        protocol = inbound["protocol"]
        transport = transport_of(protocol, s)
        for client in clients:
            if not client["eligible"]:
                continue
            secret = client["secret"]
            label = (
                inbound["node_name"]
                + " · "
                + inbound["name"]
                + " · "
                + client["device_name"]
                + " · "
                + inbound["id"][:6]
            )
            proxy = {
                "name": label,
                "type": protocol,
                "server": host,
                "port": port,
                "tls": True,
                "servername": s["sni"],
                "udp": True,
            }
            if is_reality(protocol, transport):
                query = {
                    "encryption": "none",
                    "security": "reality",
                    "sni": s["sni"],
                    "fp": "chrome",
                    "pbk": s["public_key"],
                    "sid": s["short_id"],
                    "type": "tcp",
                    "flow": "xtls-rprx-vision",
                }
                proxy.update(
                    {
                        "uuid": secret,
                        "flow": "xtls-rprx-vision",
                        "client-fingerprint": "chrome",
                        "reality-opts": {
                            "public-key": s["public_key"],
                            "short-id": s["short_id"],
                        },
                    }
                )
            elif protocol == "vmess":
                vmess = {
                    "v": "2",
                    "ps": label,
                    "add": host,
                    "port": str(port),
                    "id": secret,
                    "aid": "0",
                    "scy": "auto",
                    "net": transport,
                    "type": "gun" if transport == "grpc" else "none",
                    "host": s["sni"],
                    "path": s["service_name"] if transport == "grpc" else s["path"],
                    "tls": "tls",
                    "sni": s["sni"],
                }
                links.append(
                    "vmess://" + base64.b64encode(json.dumps(vmess).encode()).decode()
                )
                _, options = _transport_options(transport, s)
                proxy.update(
                    {
                        "uuid": secret,
                        "alterId": 0,
                        "cipher": "auto",
                        "network": transport,
                        **options,
                    }
                )
                clash.append(proxy)
                continue
            elif protocol == "vless":
                # VLESS over TLS with WS or gRPC; no Vision flow.
                extra, options = _transport_options(transport, s)
                query = {
                    "encryption": "none",
                    "security": "tls",
                    "sni": s["sni"],
                    **extra,
                }
                proxy.update({"uuid": secret, "network": transport, **options})
            else:
                extra, options = _transport_options(transport, s)
                query = {"security": "tls", "sni": s["sni"], **extra}
                proxy["password"] = secret
                if transport != "tcp":
                    proxy.update({"network": transport, **options})
            links.append(
                f"{protocol}://{secret}@{address}:{port}?{urlencode(query)}#{quote(label)}"
            )
            clash.append(proxy)
    return links, {
        "proxies": clash,
        "proxy-groups": [
            {
                "name": "Donino",
                "type": "select",
                "proxies": [p["name"] for p in clash] or ["DIRECT"],
            }
        ],
        "rules": ["MATCH,Donino"],
    }
