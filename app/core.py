"""Independent Xray compiler and client profile serializers."""

import base64
import hashlib
import json
import time
from urllib.parse import urlencode, quote


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


def compile_config(inbounds, users):
    live = [u for u in users if eligible(u)]
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
        clients = [
            {
                "email": u["id"],
                "level": 0,
                ("password" if protocol == "trojan" else "id"): u["credential"],
            }
            for u in live
        ]
        if protocol == "vless":
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
            stream = {
                "network": "ws" if protocol == "vmess" else "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {"certificateFile": s["cert_file"], "keyFile": s["key_file"]}
                    ]
                },
            }
            if protocol == "vmess":
                stream["wsSettings"] = {"path": s["path"]}
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


def profiles(user, inbounds):
    links, clash = [], []
    for inbound in inbounds:
        if not inbound["enabled"] or not inbound["node_enabled"]:
            continue
        s = json.loads(inbound["settings"])
        host = inbound["host"]
        address = f"[{host}]" if ":" in host else host
        port = inbound["port"]
        label = (
            inbound["node_name"] + " · " + inbound["name"] + " · " + inbound["id"][:6]
        )
        protocol = inbound["protocol"]
        proxy = {
            "name": label,
            "type": protocol,
            "server": host,
            "port": port,
            "tls": True,
            "servername": s["sni"],
            "udp": True,
        }
        if protocol == "vless":
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
                    "uuid": user["credential"],
                    "flow": "xtls-rprx-vision",
                    "client-fingerprint": "chrome",
                    "reality-opts": {
                        "public-key": s["public_key"],
                        "short-id": s["short_id"],
                    },
                }
            )
        elif protocol == "trojan":
            query = {"security": "tls", "sni": s["sni"], "type": "tcp"}
            proxy["password"] = user["credential"]
        else:
            vmess = {
                "v": "2",
                "ps": label,
                "add": host,
                "port": str(port),
                "id": user["credential"],
                "aid": "0",
                "scy": "auto",
                "net": "ws",
                "type": "none",
                "host": s["sni"],
                "path": s["path"],
                "tls": "tls",
                "sni": s["sni"],
            }
            links.append(
                "vmess://" + base64.b64encode(json.dumps(vmess).encode()).decode()
            )
            proxy.update(
                {
                    "uuid": user["credential"],
                    "alterId": 0,
                    "cipher": "auto",
                    "network": "ws",
                    "ws-opts": {"path": s["path"], "headers": {"Host": s["sni"]}},
                }
            )
            clash.append(proxy)
            continue
        links.append(
            f"{protocol}://{user['credential']}@{address}:{port}?{urlencode(query)}#{quote(label)}"
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
