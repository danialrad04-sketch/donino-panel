"""Typed engine boundary. Register a protocol only after its real-client acceptance."""

from typing import Protocol

from .core import compile_config
from .shadowsocks import METHODS as SS_METHODS


class EngineAdapter(Protocol):
    name: str

    def compile(self, inbounds, clients) -> dict: ...

    def capabilities(self) -> dict: ...


class XrayAdapter:
    name = "xray"

    def compile(self, inbounds, clients):
        if any(
            row["protocol"] not in ("vless", "vmess", "trojan", "shadowsocks")
            for row in inbounds
        ):
            raise ValueError("Unsupported Xray protocol")
        return compile_config(inbounds, clients)

    def capabilities(self):
        return {
            "engine": self.name,
            "profiles": [
                {
                    "protocol": "vless",
                    "transport": "tcp",
                    "security": "reality",
                    "flow": "xtls-rprx-vision",
                },
                {"protocol": "vless", "transport": "ws", "security": "tls"},
                {"protocol": "vless", "transport": "grpc", "security": "tls"},
                {"protocol": "vmess", "transport": "ws", "security": "tls"},
                {"protocol": "vmess", "transport": "grpc", "security": "tls"},
                {"protocol": "trojan", "transport": "tcp", "security": "tls"},
                {"protocol": "trojan", "transport": "ws", "security": "tls"},
                {
                    "protocol": "shadowsocks",
                    "transport": "tcp",
                    "udp": True,
                    "security": "aead",
                    "methods": list(SS_METHODS),
                    "revocation": "restart",
                    "live_additions": False,
                },
            ],
            "live_additions": True,
            "revocation": "restart",
            "usage_generation": True,
        }


XRAY: EngineAdapter = XrayAdapter()
