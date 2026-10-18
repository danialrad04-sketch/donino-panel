"""Independent per-device WireGuard credentials and signed node intent."""

import base64
import hashlib
import ipaddress
import json
import io
import secrets
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field, field_validator

from .accounting import apply_sample
from .db import audit, database
from .deps import node_auth, one, owner
from .node_identity import sign_desired
from .secrets import seal, unseal
from .tunnel_bridge import Input, validate_host
from .tunnel_api import PrivateValidationRoute


def keys():
    key = X25519PrivateKey.generate()
    return tuple(
        base64.b64encode(k).decode()
        for k in (key.private_bytes_raw(), key.public_key().public_bytes_raw())
    )


def rotate_device_keys(db, device_id):
    for peer in db.execute(
        "SELECT id FROM wg_peers WHERE device_id=?", (device_id,)
    ).fetchall():
        private, public = keys()
        db.execute(
            "UPDATE wg_peers SET private_key=?,public_key=?,preshared_key=?,generation=? WHERE id=?",
            (
                seal(private),
                public,
                seal(base64.b64encode(secrets.token_bytes(32)).decode()),
                uuid.uuid4().hex,
                peer[0],
            ),
        )


class EndpointInput(Input):
    node_id: uuid.UUID = Field(strict=False)
    name: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=51820, ge=1024, le=65535)
    pool: str = "10.66.0.0/24"
    dns: list[str] = Field(default_factory=list, max_length=2)
    routes: list[str] = Field(
        default_factory=lambda: ["0.0.0.0/0"], min_length=1, max_length=16
    )

    _host = field_validator("host")(validate_host)

    @field_validator("pool")
    @classmethod
    def pool_valid(cls, value):
        net = ipaddress.ip_network(value, strict=True)
        private = [
            ipaddress.ip_network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]
        if (
            net.version != 4
            or not 16 <= net.prefixlen <= 28
            or not any(net.subnet_of(p) for p in private)
        ):
            raise ValueError("Use an RFC1918 IPv4 /16 through /28 pool")
        return str(net)

    @field_validator("dns")
    @classmethod
    def dns_valid(cls, value):
        addresses = [ipaddress.ip_address(v) for v in value]
        if any(v.version != 4 for v in addresses):
            raise ValueError("This endpoint serves IPv4; use IPv4 DNS")
        return [str(v) for v in addresses]

    @field_validator("routes")
    @classmethod
    def routes_valid(cls, value):
        nets = [ipaddress.ip_network(v, strict=True) for v in value]
        if any(n.version != 4 for n in nets) or len(set(nets)) != len(nets):
            raise ValueError("Unique IPv4 routes required")
        return [str(n) for n in nets]


class Toggle(Input):
    enabled: bool


class PeerInput(Input):
    device_id: uuid.UUID = Field(strict=False)


def endpoint_public(row):
    return {
        k: row[k]
        for k in (
            "id",
            "node_id",
            "name",
            "host",
            "port",
            "pool",
            "public_key",
            "enabled",
            "created",
        )
    } | {"dns": json.loads(row["dns"]), "routes": json.loads(row["routes"])}


def peer_public(row):
    return {
        k: row[k]
        for k in (
            "id",
            "endpoint_id",
            "device_id",
            "public_key",
            "address",
            "enabled",
            "generation",
            "created",
        )
    }


def client(db, endpoint, device_id):
    from .main import client_rows

    rows = client_rows(
        db, "WHERE d.id=?", (str(device_id),), node_id=endpoint["node_id"]
    )
    if not rows or not rows[0]["eligible"] or rows[0]["quota_mode"] == "lease":
        raise HTTPException(
            409,
            "دستگاه باید فعال و مجاز به نود باشد؛ سهمیهٔ lease هنوز برای WireGuard پذیرفته نیست",
        )
    return rows[0]


def profile(db, peer):
    endpoint = one(db, "wg_endpoints", peer["endpoint_id"])
    client(db, endpoint, peer["device_id"])
    node = one(db, "nodes", endpoint["node_id"])
    if not peer["enabled"] or not endpoint["enabled"] or not node["enabled"]:
        raise HTTPException(409, "peer یا نود WireGuard غیرفعال است")
    host = endpoint["host"]
    if ":" in host:
        host = "[" + host + "]"
    lines = [
        "[Interface]",
        "PrivateKey = " + unseal(peer["private_key"]),
        "Address = " + peer["address"] + "/32",
    ]
    routes = json.loads(endpoint["routes"])
    if "0.0.0.0/0" in routes:
        # No IPv6 data plane yet. Keep full-tunnel clients from bypassing via IPv6.
        routes.append("::/0")
    if json.loads(endpoint["dns"]):
        lines.append("DNS = " + ", ".join(json.loads(endpoint["dns"])))
    return "\n".join(
        lines
        + [
            "",
            "[Peer]",
            "PublicKey = " + endpoint["public_key"],
            "PresharedKey = " + unseal(peer["preshared_key"]),
            "AllowedIPs = " + ", ".join(routes),
            f"Endpoint = {host}:{endpoint['port']}",
            "PersistentKeepalive = 25",
            "",
        ]
    )


def desired(db, node_id, instance):
    from .main import client_rows, roll_periods

    roll_periods(db)
    clients = {
        c["id"]: c
        for c in client_rows(db, node_id=node_id)
        if c["eligible"] and c["quota_mode"] != "lease"
    }
    interfaces = []
    for endpoint in db.execute(
        "SELECT * FROM wg_endpoints WHERE node_id=? AND enabled=1 ORDER BY id",
        (node_id,),
    ):
        peers = []
        for peer in db.execute(
            "SELECT * FROM wg_peers WHERE endpoint_id=? AND enabled=1 ORDER BY id",
            (endpoint["id"],),
        ):
            c = clients.get(peer["device_id"])
            if not c:
                continue
            user = one(db, "users", c["user_id"])
            peers.append(
                {
                    "device_id": c["id"],
                    "user_id": c["user_id"],
                    "period_no": c["period_no"],
                    "generation": peer["generation"],
                    "public_key": peer["public_key"],
                    "preshared_key": unseal(peer["preshared_key"]),
                    "address": peer["address"],
                    "expires": user["expires"],
                    "remaining": max(0, user["quota"] - user["used"])
                    if user["quota"]
                    else None,
                }
            )
        net = ipaddress.ip_network(endpoint["pool"])
        interfaces.append(
            {
                "id": endpoint["id"],
                "name": "dnw" + endpoint["id"][:8],
                "pool": endpoint["pool"],
                "address": f"{net.network_address + 1}/{net.prefixlen}",
                "port": endpoint["port"],
                "private_key": unseal(endpoint["private_key"]),
                "public_key": endpoint["public_key"],
                "peers": peers,
            }
        )
    structural = json.loads(json.dumps(interfaces))
    for interface in structural:
        for peer in interface["peers"]:
            peer.pop("remaining")
            peer.pop("expires")
    revision = hashlib.sha256(
        json.dumps(structural, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    previous = one(db, "nodes", node_id)["config_sequence"]
    sequence = max(previous + 1, time.time_ns() // 1_000_000)
    db.execute("UPDATE nodes SET config_sequence=? WHERE id=?", (sequence, node_id))
    return sign_desired(
        {
            "kind": "wireguard-v1",
            "node_id": node_id,
            "agent_instance": instance,
            "revision": revision,
            "interfaces": interfaces,
        },
        sequence=sequence,
    )


def invalidate_restored(db):
    db.execute("UPDATE wg_endpoints SET enabled=0")
    db.execute("DELETE FROM wg_runtime")


def mount(app):
    router = APIRouter(route_class=PrivateValidationRoute)

    @router.get("/api/wireguard/endpoints")
    def endpoints(account=Depends(owner)):
        with database() as db:
            return [
                endpoint_public(r)
                for r in db.execute("SELECT * FROM wg_endpoints ORDER BY created,id")
            ]

    @router.post("/api/wireguard/endpoints", status_code=201)
    def create_endpoint(body: EndpointInput, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", str(body.node_id))
            existing = list(
                db.execute(
                    "SELECT * FROM wg_endpoints WHERE node_id=?", (str(body.node_id),)
                )
            )
            if len(existing) >= 4 or any(
                ipaddress.ip_network(r["pool"]).overlaps(
                    ipaddress.ip_network(body.pool)
                )
                or r["port"] == body.port
                for r in existing
            ):
                raise HTTPException(
                    409, "محدوده یا پورت تکراری است؛ حداکثر چهار رابط در هر نود"
                )
            private, public = keys()
            eid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO wg_endpoints VALUES(?,?,?,?,?,?,?,?,?,?,0,?)",
                (
                    eid,
                    str(body.node_id),
                    body.name,
                    body.host,
                    body.port,
                    body.pool,
                    json.dumps(body.dns),
                    json.dumps(body.routes),
                    seal(private),
                    public,
                    int(time.time()),
                ),
            )
            audit(db, account["username"], "wireguard.endpoint.create", eid)
            return endpoint_public(one(db, "wg_endpoints", eid))

    @router.put("/api/wireguard/endpoints/{eid}")
    def toggle_endpoint(eid: str, body: Toggle, account=Depends(owner)):
        with database() as db:
            one(db, "wg_endpoints", eid)
            db.execute(
                "UPDATE wg_endpoints SET enabled=? WHERE id=?", (body.enabled, eid)
            )
            audit(db, account["username"], "wireguard.endpoint.toggle", eid)
            return endpoint_public(one(db, "wg_endpoints", eid))

    @router.get("/api/wireguard/endpoints/{eid}/peers")
    def peers(eid: str, account=Depends(owner)):
        with database() as db:
            one(db, "wg_endpoints", eid)
            return [
                peer_public(r)
                for r in db.execute(
                    "SELECT * FROM wg_peers WHERE endpoint_id=? ORDER BY created,id",
                    (eid,),
                )
            ]

    @router.post("/api/wireguard/endpoints/{eid}/peers", status_code=201)
    def create_peer(eid: str, body: PeerInput, account=Depends(owner)):
        with database() as db:
            endpoint = one(db, "wg_endpoints", eid)
            client(db, endpoint, body.device_id)
            if db.execute(
                "SELECT 1 FROM wg_peers WHERE endpoint_id=? AND device_id=?",
                (eid, str(body.device_id)),
            ).fetchone():
                raise HTTPException(409, "برای این دستگاه peer موجود است")
            if (
                db.execute(
                    "SELECT COUNT(*) FROM wg_peers p JOIN wg_endpoints e ON e.id=p.endpoint_id WHERE e.node_id=?",
                    (endpoint["node_id"],),
                ).fetchone()[0]
                >= 128
            ):
                raise HTTPException(409, "ظرفیت ۱۲۸ peer در نود پر شده است")
            used = {
                p[0]
                for p in db.execute(
                    "SELECT address FROM wg_peers WHERE endpoint_id=?", (eid,)
                )
            }
            net = ipaddress.ip_network(endpoint["pool"])
            address = next(
                (
                    str(ip)
                    for ip in net.hosts()
                    if ip != net.network_address + 1 and str(ip) not in used
                ),
                None,
            )
            if not address:
                raise HTTPException(409, "محدودهٔ IP پر است")
            private, public = keys()
            pid = uuid.uuid4().hex
            psk = base64.b64encode(secrets.token_bytes(32)).decode()
            db.execute(
                "INSERT INTO wg_peers VALUES(?,?,?,?,?,?,?,1,?,?)",
                (
                    pid,
                    eid,
                    str(body.device_id),
                    seal(private),
                    public,
                    seal(psk),
                    address,
                    uuid.uuid4().hex,
                    int(time.time()),
                ),
            )
            audit(db, account["username"], "wireguard.peer.create", pid)
            return peer_public(one(db, "wg_peers", pid))

    @router.put("/api/wireguard/peers/{pid}")
    def toggle_peer(pid: str, body: Toggle, account=Depends(owner)):
        with database() as db:
            one(db, "wg_peers", pid)
            db.execute("UPDATE wg_peers SET enabled=? WHERE id=?", (body.enabled, pid))
            audit(db, account["username"], "wireguard.peer.toggle", pid)
            return peer_public(one(db, "wg_peers", pid))

    @router.post("/api/wireguard/peers/{pid}/rotate")
    def rotate_peer(pid: str, account=Depends(owner)):
        with database() as db:
            one(db, "wg_peers", pid)
            private, public = keys()
            db.execute(
                "UPDATE wg_peers SET private_key=?,public_key=?,preshared_key=?,generation=? WHERE id=?",
                (
                    seal(private),
                    public,
                    seal(base64.b64encode(secrets.token_bytes(32)).decode()),
                    uuid.uuid4().hex,
                    pid,
                ),
            )
            audit(db, account["username"], "wireguard.peer.rotate", pid)
            return peer_public(one(db, "wg_peers", pid))

    @router.get("/api/wireguard/peers/{pid}/profile")
    def download(pid: str, account=Depends(owner)):
        with database() as db:
            content = profile(db, one(db, "wg_peers", pid))
            audit(db, account["username"], "wireguard.profile.download", pid)
        return Response(
            content,
            media_type="text/plain",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="donino-wireguard.conf"',
            },
        )

    @router.get("/api/wireguard/peers/{pid}/qr")
    def qr(pid: str, account=Depends(owner)):
        import qrcode
        from qrcode.image.svg import SvgPathImage

        with database() as db:
            content = profile(db, one(db, "wg_peers", pid))
            audit(db, account["username"], "wireguard.profile.qr", pid)
        output = io.BytesIO()
        qrcode.make(content, image_factory=SvgPathImage, border=4).save(output)
        return Response(
            output.getvalue(),
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/api/agent/wireguard/config")
    def config(instance: uuid.UUID, node=Depends(node_auth)):
        with database() as db:
            return desired(db, node["id"], str(instance))

    # The imported Usage model is shared, so period accounting and dedup remain identical.
    from .main import Usage, roll_periods

    class Report(Input):
        epoch: uuid.UUID = Field(strict=False)
        instance: uuid.UUID = Field(strict=False)
        usage: list[Usage] = Field(default_factory=list, max_length=500)

    @router.post("/api/agent/wireguard/heartbeat")
    def report(body: Report, node=Depends(node_auth)):
        with database() as db:
            now = int(time.time())
            roll_periods(db, now)
            for sample in body.usage:
                if sample.period_no is None or sample.lease_id is not None:
                    raise HTTPException(409, "نسل مصرف مشخص و سهمیهٔ عادی لازم است")
                apply_sample(db, node["id"], str(body.epoch), sample, now)
            db.execute(
                "INSERT INTO wg_runtime VALUES(?,?,?,NULL) ON CONFLICT(node_id) DO UPDATE SET seen=excluded.seen,instance_id=excluded.instance_id,error_code=NULL",
                (node["id"], now, str(body.instance)),
            )
        return {"ok": True}

    app.include_router(router)
