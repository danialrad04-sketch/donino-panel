"""DNS management, proof of source-IP ownership and authenticated RFC 8484 DoH."""

import base64
import binascii
import json
import secrets
import re
import time
import uuid
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .db import audit, database, digest, upsert
from .deps import admin, owner, writer, one, public_base
from .dns_policy import DNSPolicyInput
from .dns_service import DNSService, canonical_address


class DNSAccountInput(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    policy_id: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    query_limit: int = Field(default=0, ge=0, le=9_000_000_000_000_000)
    qps: int = Field(default=20, ge=1, le=100)


class IPClaim(BaseModel):
    ttl: int = Field(default=3600, ge=60, le=86400)


def dns_accounts(db, uid=None):
    rows = db.execute(
        """SELECT a.id,a.user_id,a.policy_id,a.enabled,a.query_limit,a.qps,a.period_no,
        a.created,a.updated,u.name AS user_name,p.name AS policy_name,
        d.queries,d.request_bytes,d.response_bytes,d.errors,d.blocked
        FROM dns_accounts a JOIN users u ON u.id=a.user_id JOIN dns_policies p ON p.id=a.policy_id
        JOIN dns_periods d ON d.account_id=a.id AND d.period_no=a.period_no"""
        + (" WHERE a.user_id=?" if uid else "")
        + " ORDER BY a.created DESC LIMIT 1000",
        (uid,) if uid else (),
    ).fetchall()
    return [dict(row) for row in rows]


def portal_account(db, token):
    user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not user:
        raise HTTPException(404, "اشتراک پیدا نشد")
    if not user["enabled"] or (user["expires"] and user["expires"] <= time.time()):
        raise HTTPException(403, "اشتراک غیرفعال یا منقضی است")
    account = db.execute(
        "SELECT * FROM dns_accounts WHERE user_id=? AND enabled=1", (user["id"],)
    ).fetchone()
    if not account:
        raise HTTPException(404, "خدمت DNS فعال نیست")
    return account


def mount_dns_api(app):
    service = DNSService()
    app.state.dns_service = service

    @app.get("/api/dns/policies")
    def policies(account=Depends(admin)):
        with database() as db:
            values = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM dns_policies ORDER BY name LIMIT 1000"
                )
            ]
        for value in values:
            value["rules"] = json.loads(value["rules"])
        return values

    @app.post("/api/dns/policies", status_code=201)
    def create_policy(body: DNSPolicyInput, account=Depends(owner)):
        policy_id, revision, now = (
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            int(time.time()),
        )
        with database() as db:
            db.execute(
                "INSERT INTO dns_policies VALUES(?,?,?,?,?,?)",
                (
                    policy_id,
                    body.name,
                    revision,
                    json.dumps([rule.model_dump() for rule in body.rules]),
                    now,
                    now,
                ),
            )
            audit(db, account["username"], "dns.policy.create", policy_id)
        return {"id": policy_id, "revision": revision}

    @app.put("/api/dns/policies/{policy_id}")
    def update_policy(policy_id: str, body: DNSPolicyInput, account=Depends(owner)):
        revision = str(uuid.uuid4())
        with database() as db:
            one(db, "dns_policies", policy_id)
            db.execute(
                "UPDATE dns_policies SET name=?,revision=?,rules=?,updated=? WHERE id=?",
                (
                    body.name,
                    revision,
                    json.dumps([r.model_dump() for r in body.rules]),
                    int(time.time()),
                    policy_id,
                ),
            )
            audit(db, account["username"], "dns.policy.update", policy_id)
        return {"id": policy_id, "revision": revision}

    @app.delete("/api/dns/policies/{policy_id}")
    def delete_policy(policy_id: str, account=Depends(owner)):
        with database() as db:
            one(db, "dns_policies", policy_id)
            db.execute("DELETE FROM dns_policies WHERE id=?", (policy_id,))
            audit(db, account["username"], "dns.policy.delete", policy_id)
        return {"ok": True}

    @app.get("/api/dns/accounts")
    def accounts(account=Depends(admin)):
        with database() as db:
            return dns_accounts(db)

    @app.post("/api/dns/accounts", status_code=201)
    def create_account(body: DNSAccountInput, account=Depends(writer)):
        account_id, token, now = (
            str(uuid.uuid4()),
            "dns_" + secrets.token_urlsafe(32),
            int(time.time()),
        )
        with database() as db:
            one(db, "users", body.user_id)
            one(db, "dns_policies", body.policy_id)
            db.execute(
                """INSERT INTO dns_accounts(id,user_id,policy_id,token_hash,enabled,query_limit,qps,created,updated)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    account_id,
                    body.user_id,
                    body.policy_id,
                    digest(token),
                    int(body.enabled),
                    body.query_limit,
                    body.qps,
                    now,
                    now,
                ),
            )
            db.execute(
                "INSERT INTO dns_periods(account_id,period_no,created) VALUES(?,0,?)",
                (account_id, now),
            )
            audit(db, account["username"], "dns.account.create", account_id)
        return {"id": account_id, "token": token, "doh_path": "/dns-query"}

    @app.put("/api/dns/accounts/{account_id}")
    def update_account(account_id: str, body: DNSAccountInput, account=Depends(writer)):
        with database() as db:
            current = one(db, "dns_accounts", account_id)
            if current["user_id"] != body.user_id:
                raise HTTPException(409, "مالک خدمت DNS قابل انتقال نیست")
            one(db, "dns_policies", body.policy_id)
            db.execute(
                "UPDATE dns_accounts SET policy_id=?,enabled=?,query_limit=?,qps=?,updated=? WHERE id=?",
                (
                    body.policy_id,
                    int(body.enabled),
                    body.query_limit,
                    body.qps,
                    int(time.time()),
                    account_id,
                ),
            )
            audit(db, account["username"], "dns.account.update", account_id)
        return {"ok": True}

    @app.post("/api/dns/accounts/{account_id}/rotate-token")
    def rotate_token(account_id: str, account=Depends(writer)):
        token = "dns_" + secrets.token_urlsafe(32)
        with database() as db:
            one(db, "dns_accounts", account_id)
            db.execute(
                "UPDATE dns_accounts SET token_hash=?,updated=? WHERE id=?",
                (digest(token), int(time.time()), account_id),
            )
            audit(db, account["username"], "dns.token.rotate", account_id)
        return {"token": token, "doh_path": "/dns-query"}

    @app.post("/api/dns/accounts/{account_id}/reset")
    def reset(account_id: str, account=Depends(writer)):
        now = int(time.time())
        with database() as db:
            current = one(db, "dns_accounts", account_id)
            db.execute(
                "UPDATE dns_periods SET closed=? WHERE account_id=? AND period_no=?",
                (now, account_id, current["period_no"]),
            )
            db.execute(
                "UPDATE dns_accounts SET period_no=period_no+1,updated=? WHERE id=?",
                (now, account_id),
            )
            db.execute(
                "INSERT INTO dns_periods(account_id,period_no,created) VALUES(?,?,?)",
                (account_id, current["period_no"] + 1, now),
            )
            audit(db, account["username"], "dns.period.reset", account_id)
        return {"ok": True}

    @app.get("/api/dns/accounts/{account_id}/periods")
    def periods(account_id: str, account=Depends(admin)):
        with database() as db:
            one(db, "dns_accounts", account_id)
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM dns_periods WHERE account_id=? ORDER BY period_no DESC LIMIT 100",
                    (account_id,),
                )
            ]

    @app.delete("/api/dns/accounts/{account_id}")
    def delete_account(account_id: str, account=Depends(writer)):
        with database() as db:
            one(db, "dns_accounts", account_id)
            db.execute("DELETE FROM dns_accounts WHERE id=?", (account_id,))
            audit(db, account["username"], "dns.account.delete", account_id)
        return {"ok": True}

    @app.get("/api/portal/{token}/dns")
    def portal_dns(token: str, request: Request):
        with database() as db:
            account = portal_account(db, token)
            value = dns_accounts(db, account["user_id"])[0]
            value["ip_leases"] = [
                dict(r)
                for r in db.execute(
                    "SELECT ip,expires FROM dns_ip_leases WHERE account_id=? AND expires>?",
                    (account["id"], int(time.time())),
                )
            ]
            value["doh_url"] = public_base(request) + "/dns-query"
            value["server_name"] = urlsplit(public_base(request)).hostname
        return value

    @app.post("/api/portal/{token}/dns/rotate-token")
    def portal_rotate_token(token: str):
        credential = "dns_" + secrets.token_urlsafe(32)
        with database() as db:
            account = portal_account(db, token)
            db.execute(
                "UPDATE dns_accounts SET token_hash=?,updated=? WHERE id=?",
                (digest(credential), int(time.time()), account["id"]),
            )
            audit(db, "portal:" + account["user_id"], "dns.token.rotate", account["id"])
        return {"token": credential, "doh_path": "/dns-query"}

    @app.post("/api/portal/{token}/dns/claim-ip")
    def claim_ip(token: str, body: IPClaim, request: Request):
        # Trust the socket peer. The managed reverse proxy overwrites forwarded
        # headers and uvicorn trusts only loopback; never read arbitrary XFF here.
        try:
            ip = canonical_address(request.client.host if request.client else "")
        except ValueError as exc:
            raise HTTPException(422, "نشانی عمومی اتصال قابل تشخیص نیست") from exc
        if not ip.is_global or ip.is_multicast:
            raise HTTPException(422, "برای اثبات IP باید از همان نشانی عمومی متصل شوید")
        now = int(time.time())
        with database() as db:
            account = portal_account(db, token)
            db.execute("DELETE FROM dns_ip_leases WHERE expires<=?", (now,))
            old = db.execute(
                "SELECT * FROM dns_ip_leases WHERE ip=?", (str(ip),)
            ).fetchone()
            if old and old["account_id"] != account["id"]:
                raise HTTPException(
                    409,
                    "این IP مشترک به حساب دیگری متصل است؛ از DoH احرازشده یا تونل استفاده کنید",
                )
            count = db.execute(
                "SELECT COUNT(*) FROM dns_ip_leases WHERE account_id=?",
                (account["id"],),
            ).fetchone()[0]
            if not old and count >= 3:
                raise HTTPException(409, "حداکثر سه IP هم‌زمان مجاز است")
            expires = now + body.ttl
            upsert(
                db,
                "dns_ip_leases",
                ["ip", "account_id", "expires", "created"],
                [str(ip), account["id"], expires, old["created"] if old else now],
                ["ip"],
            )
            audit(db, "portal:" + account["user_id"], "dns.ip.claim", str(ip))
        return {"ip": str(ip), "expires": expires}

    @app.delete("/api/portal/{token}/dns/ip-leases")
    def release_ips(token: str):
        with database() as db:
            account = portal_account(db, token)
            db.execute("DELETE FROM dns_ip_leases WHERE account_id=?", (account["id"],))
            audit(db, "portal:" + account["user_id"], "dns.ip.release", account["id"])
        return {"ok": True}

    @app.api_route("/dns-query", methods=["GET", "POST"])
    async def doh(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer dns_"):
            raise HTTPException(401, "Use a separate DNS Bearer credential")
        if request.method == "GET":
            encoded = request.query_params.get("dns", "")
            if (
                not encoded
                or len(encoded) > 5464
                or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded)
            ):
                raise HTTPException(400, "Missing or oversized DNS query")
            try:
                wire = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise HTTPException(400, "Invalid base64url DNS query") from exc
        else:
            if (
                request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                != "application/dns-message"
            ):
                raise HTTPException(415, "Use application/dns-message")
            wire = await request.body()
        try:
            output = await run_in_threadpool(service.answer, wire, token=auth[7:])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return Response(
            output,
            media_type="application/dns-message",
            headers={"Cache-Control": "no-store"},
        )
