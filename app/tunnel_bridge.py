"""Opt-in bridge to Donino Tunnel's local typed controller, never a shell API."""

import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SOCKET = Path("/run/donino-control/control.sock")
MAX_RESPONSE = 2 * 1024 * 1024
SUPPORTED = ("frp-wss", "frp-quic")
ID = r"^[0-9a-f]{32}$"


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def validate_host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(
            r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value
        ):
            raise ValueError("Use an IP or DNS name without scheme or port") from None
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in value.split(".")
        ):
            raise ValueError("Invalid DNS name") from None
        return value.lower()


class PairInput(Input):
    name: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=253)
    agent_port: int = Field(default=9444, ge=1024, le=65535)
    code: str = Field(pattern=r"^donino1\.[0-9a-f]{64}\.[A-Za-z0-9_-]{43}$")

    _host = field_validator("host")(validate_host)


class ConnectionInput(Input):
    profile_id: str = Field(pattern=ID)


class ServiceInput(Input):
    id: str = Field(min_length=1, max_length=40, pattern=r"^[a-z][a-z0-9-]*$")
    listen_port: int = Field(ge=1, le=65535)
    target_port: int = Field(ge=1, le=65535)


class PreviewInput(ConnectionInput):
    iran: str = Field(min_length=1, max_length=253)
    services: list[ServiceInput] = Field(min_length=1, max_length=40)
    transports: list[Literal["frp-wss", "frp-quic"]] = Field(min_length=1, max_length=2)
    base_port: int = Field(default=30000, ge=1024, le=65000)
    carrier_base: int = Field(default=24443, ge=1024, le=65000)
    health_port: int = Field(default=19090, ge=1024, le=65535)

    _iran = field_validator("iran")(validate_host)

    @model_validator(mode="after")
    def unique(self):
        if len(set(self.transports)) != len(self.transports):
            raise ValueError("Duplicate carrier")
        for field in ("id", "listen_port"):
            if len({getattr(row, field) for row in self.services}) != len(
                self.services
            ):
                raise ValueError("Duplicate service or public port")
        return self

    def worker_spec(self):
        return {
            "profile_id": self.profile_id,
            "iran": self.iran,
            "services": [
                {
                    "id": row.id,
                    "listen": f"0.0.0.0:{row.listen_port}",
                    "target": f"127.0.0.1:{row.target_port}",
                    "protocol": "tcp",
                }
                for row in self.services
            ],
            "transports": self.transports,
            "base_port": self.base_port,
            "carrier_base": self.carrier_base,
            "health_port": self.health_port,
            "experimental": False,
            "open_ufw": False,
        }


class StartInput(Input):
    plan_id: str = Field(pattern=ID)
    confirm_replace: Literal[True]

    @field_validator("confirm_replace", mode="before")
    @classmethod
    def explicit_confirmation(cls, value):
        if value is not True:
            raise ValueError("Explicit confirmation is required")
        return value


class Public(BaseModel):
    """Whitelist responses; upstream inventories, specs and credentials stay local."""

    model_config = ConfigDict(extra="ignore")


class Profile(Public):
    id: str = Field(pattern=ID)
    name: str
    host: str
    management: str = ""


class Connection(Public):
    ok: bool
    time: float | None = None
    ready: bool = False
    runtime_match: bool = False
    version: str | None = None


class Job(Public):
    id: str = Field(pattern=ID)
    plan_id: str = Field(pattern=ID)
    status: Literal["running", "succeeded", "failed", "interrupted", "rollback_failed"]
    stage: str
    created: float
    updated: float


class State(Public):
    available: bool
    busy: bool
    iran_address: str | None = None
    profiles: list[Profile] = Field(max_length=20)
    jobs: list[Job] = Field(max_length=20)


class PublicService(Public):
    id: str
    listen: str
    target: str
    protocol: str = "tcp"


class Firewall(Public):
    tcp: list[int]
    udp: list[int]


class Summary(Public):
    iran: str
    foreign: str
    transports: list[str]
    services: list[PublicService]
    firewall: dict[Literal["iran", "foreign"], Firewall]


class Preview(Public):
    id: str = Field(pattern=ID)
    expires_at: float
    summary: Summary


class BridgeError(Exception):
    def __init__(self, status=503):
        self.status = status


def enabled():
    return os.environ.get("DONINO_TUNNEL_BRIDGE", "") == "1"


class TunnelClient:
    def __init__(self, path=SOCKET, *, require_root=True):
        self.path, self.require_root = Path(path), require_root

    def check_socket(self):
        try:
            info = self.path.lstat()
        except OSError:
            raise BridgeError() from None
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_mode & 0o007
            or (self.require_root and info.st_uid != 0)
        ):
            raise BridgeError()

    def request(self, method, route, body=None):
        if (method, route) not in {
            ("GET", "/state"),
            ("POST", "/pair"),
            ("POST", "/connection"),
            ("POST", "/preview"),
            ("POST", "/start"),
        }:
            raise BridgeError(400)
        self.check_socket()
        try:
            transport = httpx.HTTPTransport(uds=str(self.path))
            with httpx.Client(
                transport=transport, trust_env=False, follow_redirects=False, timeout=90
            ) as client:
                with client.stream(
                    method, "http://localhost" + route, json=body
                ) as response:
                    if response.status_code not in (200, 201, 202):
                        # Never echo arbitrary upstream errors (may include secrets).
                        raise BridgeError(409 if response.status_code == 400 else 502)
                    payload = bytearray()
                    for chunk in response.iter_bytes():
                        payload.extend(chunk)
                        if len(payload) > MAX_RESPONSE:
                            raise BridgeError(502)
            import json

            value = json.loads(payload)
            if not isinstance(value, dict):
                raise BridgeError(502)
            return value
        except (httpx.HTTPError, OSError, ValueError):
            # A timeout may happen AFTER a mutation; callers must inspect state.
            raise BridgeError(502) from None
