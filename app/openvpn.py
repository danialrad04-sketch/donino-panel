"""Managed OpenVPN endpoints, independent device certificates and signed intent."""

import hashlib
import ipaddress
import json
import time
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field

from . import openvpn_pki as pki
from .accounting import apply_sample
from .db import audit, database
from .deps import node_auth, one, owner
from .node_identity import sign_desired
from .secrets import seal, unseal
from .tunnel_api import PrivateValidationRoute
from .wireguard import EndpointInput as NetworkInput, PeerInput, Toggle


class EndpointInput(NetworkInput):
    port: int = Field(default=1194, ge=1024, le=65535)
    protocol: Literal["udp", "tcp"] = "udp"
    pool: str = "10.67.0.0/24"


def eligible(db, endpoint, device_id):
    from .main import client_rows

    rows = client_rows(
        db, "WHERE d.id=?", (str(device_id),), node_id=endpoint["node_id"]
    )
    if not rows or not rows[0]["eligible"] or rows[0]["quota_mode"] == "lease":
        raise HTTPException(
            409, "دستگاه باید فعال و مجاز به نود باشد؛ OpenVPN هنوز سهمیهٔ lease ندارد"
        )
    return rows[0]


def endpoint_public(row):
    return {
        k: row[k]
        for k in (
            "id",
            "node_id",
            "name",
            "host",
            "port",
            "protocol",
            "pool",
            "enabled",
            "created",
        )
    } | {
        "dns": json.loads(row["dns"]),
        "routes": json.loads(row["routes"]),
        "ca_fingerprint": pki.fingerprint(row["ca_cert"]),
        "server_name": "donino-" + row["id"],
        "ca_expires": pki.expires(row["ca_cert"]),
        "server_expires": pki.expires(row["server_cert"]),
    }


def peer_public(row):
    return {
        k: row[k]
        for k in (
            "id",
            "endpoint_id",
            "device_id",
            "address",
            "serial",
            "generation",
            "enabled",
            "created",
        )
    }


def rotate_device_keys(db, device_id):
    for peer in db.execute(
        "SELECT * FROM ovpn_peers WHERE device_id=?", (device_id,)
    ).fetchall():
        endpoint = one(db, "ovpn_endpoints", peer["endpoint_id"])
        private, cert, serial = pki.issue(
            unseal(endpoint["ca_key"]), endpoint["ca_cert"], peer["id"]
        )
        db.execute(
            "UPDATE ovpn_peers SET private_key=?,certificate=?,serial=?,generation=? WHERE id=?",
            (seal(private), cert, serial, uuid.uuid4().hex, peer["id"]),
        )


def profile(db, peer):
    endpoint = one(db, "ovpn_endpoints", peer["endpoint_id"])
    eligible(db, endpoint, peer["device_id"])
    if (
        min(pki.expires(peer["certificate"]), pki.expires(endpoint["ca_cert"]))
        <= time.time()
    ):
        raise HTTPException(409, "گواهی OpenVPN منقضی است؛ گواهی دستگاه را تعویض کنید")
    node = one(db, "nodes", endpoint["node_id"])
    if not peer["enabled"] or not endpoint["enabled"] or not node["enabled"]:
        raise HTTPException(409, "دستگاه یا نود OpenVPN غیرفعال است")
    lines = [
        "client",
        "dev tun",
        "tun-mtu 1420",
        "proto " + ("udp4" if endpoint["protocol"] == "udp" else "tcp4-client"),
        f"remote {endpoint['host']} {endpoint['port']}",
        "nobind",
        "persist-key",
        "remote-cert-tls server",
        "verify-x509-name donino-" + endpoint["id"] + " name",
        "tls-version-min 1.2",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "auth SHA256",
        "auth-nocache",
        "allow-compression no",
        "verb 0",
    ]
    for route in json.loads(endpoint["routes"]):
        net = ipaddress.ip_network(route)
        if net.prefixlen == 0:
            # IPv6 data-plane is not offered; route it to the client's explicit
            # OpenVPN IPv6 blocker instead of leaking through the physical NIC.
            prefix = "fd42:" + endpoint["id"][:4] + ":" + endpoint["id"][4:8]
            lines += [
                "redirect-gateway def1 ipv6",
                "block-ipv6",
                "route-ipv6 ::/0",
                f"ifconfig-ipv6 {prefix}::2/64 {prefix}::1",
            ]
        else:
            lines.append(f"route {net.network_address} {net.netmask}")
    lines += ["dhcp-option DNS " + address for address in json.loads(endpoint["dns"])]
    for name, value in (
        ("ca", endpoint["ca_cert"]),
        ("cert", peer["certificate"]),
        ("key", unseal(peer["private_key"])),
        ("tls-crypt", unseal(endpoint["tls_key"])),
    ):
        lines += [f"<{name}>", value.strip(), f"</{name}>"]
    return "\n".join(lines) + "\n"


def desired(db, node_id, instance):
    from .main import client_rows, roll_periods

    roll_periods(db)
    clients = {
        c["id"]: c
        for c in client_rows(db, node_id=node_id)
        if c["eligible"] and c["quota_mode"] != "lease"
    }
    interfaces = []
    for e in db.execute(
        "SELECT * FROM ovpn_endpoints WHERE node_id=? AND enabled=1 ORDER BY id",
        (node_id,),
    ):
        if pki.expires(e["ca_cert"]) <= time.time():
            continue
        if pki.expires(e["server_cert"]) <= time.time() + 7 * 86400:
            key, cert, _ = pki.issue(
                unseal(e["ca_key"]), e["ca_cert"], "donino-" + e["id"], server=True
            )
            db.execute(
                "UPDATE ovpn_endpoints SET server_key=?,server_cert=? WHERE id=?",
                (seal(key), cert, e["id"]),
            )
            e = dict(e) | {"server_key": seal(key), "server_cert": cert}
        peers = []
        for p in db.execute(
            "SELECT * FROM ovpn_peers WHERE endpoint_id=? AND enabled=1 ORDER BY id",
            (e["id"],),
        ):
            c = clients.get(p["device_id"])
            if not c:
                continue
            user = one(db, "users", c["user_id"])
            expiry = min(
                pki.expires(p["certificate"]),
                pki.expires(e["server_cert"]),
                pki.expires(e["ca_cert"]),
            )
            if user["expires"] is not None:
                expiry = min(expiry, user["expires"])
            if expiry <= time.time():
                continue
            peers.append(
                {
                    "device_id": c["id"],
                    "user_id": c["user_id"],
                    "period_no": c["period_no"],
                    "generation": p["generation"],
                    "public_key": p["id"],
                    "serial": p["serial"],
                    "address": p["address"],
                    "expires": expiry,
                    "remaining": max(0, user["quota"] - user["used"])
                    if user["quota"]
                    else None,
                }
            )
        net = ipaddress.ip_network(e["pool"])
        interfaces.append(
            {
                "id": e["id"],
                "name": "dno" + e["id"][:8],
                "pool": e["pool"],
                "address": f"{net.network_address + 1}/{net.prefixlen}",
                "port": e["port"],
                "protocol": e["protocol"],
                "ca_cert": e["ca_cert"],
                "server_cert": e["server_cert"],
                "private_key": unseal(e["server_key"]),
                "public_key": pki.fingerprint(e["server_cert"]),
                "tls_key": unseal(e["tls_key"]),
                "peers": peers,
            }
        )
    structural = json.loads(json.dumps(interfaces))
    for i in structural:
        for p in i["peers"]:
            p.pop("remaining")
            p.pop("expires")
    revision = hashlib.sha256(
        json.dumps(structural, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    previous = one(db, "nodes", node_id)["config_sequence"]
    sequence = max(previous + 1, time.time_ns() // 1_000_000)
    db.execute("UPDATE nodes SET config_sequence=? WHERE id=?", (sequence, node_id))
    return sign_desired(
        {
            "kind": "openvpn-v1",
            "node_id": node_id,
            "agent_instance": instance,
            "revision": revision,
            "interfaces": interfaces,
        },
        sequence=sequence,
    )


def invalidate_restored(db):
    db.execute("UPDATE ovpn_endpoints SET enabled=0")
    db.execute("DELETE FROM ovpn_runtime")


def mount(app):
    router = APIRouter(route_class=PrivateValidationRoute)

    @router.get("/api/openvpn/endpoints")
    def endpoints(account=Depends(owner)):
        with database() as db:
            return [
                endpoint_public(e)
                for e in db.execute("SELECT * FROM ovpn_endpoints ORDER BY created,id")
            ]

    @router.post("/api/openvpn/endpoints", status_code=201)
    def create_endpoint(body: EndpointInput, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", str(body.node_id))
            try:
                if ipaddress.ip_address(body.host).version == 6:
                    raise HTTPException(
                        422, "این پیش‌نمایش OpenVPN فقط روی IPv4 گوش می‌دهد"
                    )
            except ValueError:
                pass
            existing = list(
                db.execute(
                    "SELECT * FROM ovpn_endpoints WHERE node_id=?", (str(body.node_id),)
                )
            )
            pools = existing + list(
                db.execute(
                    "SELECT * FROM wg_endpoints WHERE node_id=?", (str(body.node_id),)
                )
            )
            if len(existing) >= 4 or any(
                ipaddress.ip_network(e["pool"]).overlaps(
                    ipaddress.ip_network(body.pool)
                )
                for e in pools
            ):
                raise HTTPException(
                    409, "محدوده تکراری است یا ظرفیت چهار رابط پر شده است"
                )
            if any(
                e["port"] == body.port and e["protocol"] == body.protocol
                for e in existing
            ):
                raise HTTPException(409, "پورت و پروتکل تکراری است")
            eid = uuid.uuid4().hex
            ca_key, ca_cert = pki.authority(eid)
            key, cert, _ = pki.issue(ca_key, ca_cert, "donino-" + eid, server=True)
            db.execute(
                "INSERT INTO ovpn_endpoints(id,node_id,name,host,port,protocol,pool,dns,routes,ca_key,ca_cert,server_key,server_cert,tls_key,enabled,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                (
                    eid,
                    str(body.node_id),
                    body.name,
                    body.host,
                    body.port,
                    body.protocol,
                    body.pool,
                    json.dumps(body.dns),
                    json.dumps(body.routes),
                    seal(ca_key),
                    ca_cert,
                    seal(key),
                    cert,
                    seal(pki.tls_crypt_key()),
                    int(time.time()),
                ),
            )
            audit(db, account["username"], "openvpn.endpoint.create", eid)
            return endpoint_public(one(db, "ovpn_endpoints", eid))

    @router.put("/api/openvpn/endpoints/{eid}")
    def toggle_endpoint(eid: str, body: Toggle, account=Depends(owner)):
        with database() as db:
            one(db, "ovpn_endpoints", eid)
            db.execute(
                "UPDATE ovpn_endpoints SET enabled=? WHERE id=?", (body.enabled, eid)
            )
            audit(db, account["username"], "openvpn.endpoint.toggle", eid)
            return endpoint_public(one(db, "ovpn_endpoints", eid))

    @router.delete("/api/openvpn/endpoints/{eid}", status_code=204)
    def delete_endpoint(eid: str, account=Depends(owner)):
        with database() as db:
            e = one(db, "ovpn_endpoints", eid)
            if e["enabled"]:
                raise HTTPException(409, "ابتدا رابط را غیرفعال کنید")
            db.execute("DELETE FROM ovpn_endpoints WHERE id=?", (eid,))
            audit(db, account["username"], "openvpn.endpoint.delete", eid)
        return Response(status_code=204)

    @router.get("/api/openvpn/endpoints/{eid}/peers")
    def peers(eid: str, account=Depends(owner)):
        with database() as db:
            one(db, "ovpn_endpoints", eid)
            return [
                peer_public(p)
                for p in db.execute(
                    "SELECT * FROM ovpn_peers WHERE endpoint_id=? ORDER BY created,id",
                    (eid,),
                )
            ]

    @router.post("/api/openvpn/endpoints/{eid}/peers", status_code=201)
    def create_peer(eid: str, body: PeerInput, account=Depends(owner)):
        with database() as db:
            e = one(db, "ovpn_endpoints", eid)
            eligible(db, e, body.device_id)
            if db.execute(
                "SELECT 1 FROM ovpn_peers WHERE endpoint_id=? AND device_id=?",
                (eid, str(body.device_id)),
            ).fetchone():
                raise HTTPException(409, "این دستگاه گواهی دارد")
            count = db.execute(
                "SELECT COUNT(*) FROM ovpn_peers p JOIN ovpn_endpoints e ON p.endpoint_id=e.id WHERE e.node_id=?",
                (e["node_id"],),
            ).fetchone()[0]
            if count >= 128:
                raise HTTPException(409, "ظرفیت ۱۲۸ دستگاه پر است")
            used = {
                p[0]
                for p in db.execute(
                    "SELECT address FROM ovpn_peers WHERE endpoint_id=?", (eid,)
                )
            }
            net = ipaddress.ip_network(e["pool"])
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
            pid = uuid.uuid4().hex
            key, cert, serial = pki.issue(unseal(e["ca_key"]), e["ca_cert"], pid)
            db.execute(
                "INSERT INTO ovpn_peers VALUES(?,?,?,?,?,?,?, ?,1,?)",
                (
                    pid,
                    eid,
                    str(body.device_id),
                    address,
                    seal(key),
                    cert,
                    serial,
                    uuid.uuid4().hex,
                    int(time.time()),
                ),
            )
            audit(db, account["username"], "openvpn.peer.create", pid)
            return peer_public(one(db, "ovpn_peers", pid))

    @router.put("/api/openvpn/peers/{pid}")
    def toggle_peer(pid: str, body: Toggle, account=Depends(owner)):
        with database() as db:
            one(db, "ovpn_peers", pid)
            db.execute(
                "UPDATE ovpn_peers SET enabled=? WHERE id=?", (body.enabled, pid)
            )
            audit(db, account["username"], "openvpn.peer.toggle", pid)
            return peer_public(one(db, "ovpn_peers", pid))

    @router.post("/api/openvpn/peers/{pid}/rotate")
    def rotate_peer(pid: str, account=Depends(owner)):
        with database() as db:
            p = one(db, "ovpn_peers", pid)
            e = one(db, "ovpn_endpoints", p["endpoint_id"])
            key, cert, serial = pki.issue(unseal(e["ca_key"]), e["ca_cert"], pid)
            db.execute(
                "UPDATE ovpn_peers SET private_key=?,certificate=?,serial=?,generation=? WHERE id=?",
                (seal(key), cert, serial, uuid.uuid4().hex, pid),
            )
            audit(db, account["username"], "openvpn.peer.rotate", pid)
            return peer_public(one(db, "ovpn_peers", pid))

    @router.delete("/api/openvpn/peers/{pid}", status_code=204)
    def delete_peer(pid: str, account=Depends(owner)):
        with database() as db:
            p = one(db, "ovpn_peers", pid)
            if p["enabled"]:
                raise HTTPException(409, "ابتدا دسترسی را لغو کنید")
            db.execute("DELETE FROM ovpn_peers WHERE id=?", (pid,))
            audit(db, account["username"], "openvpn.peer.delete", pid)
        return Response(status_code=204)

    @router.get("/api/openvpn/peers/{pid}/profile")
    def download(pid: str, account=Depends(owner)):
        with database() as db:
            value = profile(db, one(db, "ovpn_peers", pid))
        return Response(
            value,
            media_type="application/x-openvpn-profile",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="donino.ovpn"',
            },
        )

    @router.get("/api/agent/openvpn/config")
    def config(instance: uuid.UUID, node=Depends(node_auth)):
        with database() as db:
            return desired(db, node["id"], str(instance))

    from .main import Usage, roll_periods
    from .tunnel_bridge import Input

    class Report(Input):
        epoch: uuid.UUID = Field(strict=False)
        instance: uuid.UUID = Field(strict=False)
        usage: list[Usage] = Field(default_factory=list, max_length=500)

    @router.post("/api/agent/openvpn/heartbeat")
    def report(body: Report, node=Depends(node_auth)):
        with database() as db:
            now = int(time.time())
            roll_periods(db, now)
            for sample in body.usage:
                if sample.period_no is None or sample.lease_id is not None:
                    raise HTTPException(409, "دورهٔ مشخص و سهمیهٔ عادی لازم است")
                apply_sample(db, node["id"], str(body.epoch), sample, now)
            db.execute(
                "INSERT INTO ovpn_runtime VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET seen=excluded.seen,instance_id=excluded.instance_id",
                (node["id"], now, str(body.instance)),
            )
        return {"ok": True}

    app.include_router(router)
