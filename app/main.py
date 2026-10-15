import base64
import io
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import qrcode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from qrcode.image.svg import SvgPathImage
from sqlalchemy.exc import IntegrityError

from . import __version__
from .core import compile_config, eligible, revision, status
from .db import audit, database, digest, initialize, verify_password
from .identity import (
    apply_usage,
    connection_users,
    ensure_identity,
    profile_sets,
    reset_period,
)
from .identity_api import mount_identity_routes
from .security import verify_factor


@asynccontextmanager
async def lifespan(app):
    initialize()
    yield


app = FastAPI(
    title="Donino Panel",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def security_headers(request, call_next):
    # Cookie authentication mutations require a header unavailable to HTML forms.
    # No CORS is enabled. Also reject cross-origin requests with an Origin header.
    if request.method in ("POST", "PATCH", "DELETE", "PUT"):
        if request.headers.get("origin") and request.headers["origin"] != str(
            request.base_url
        ).rstrip("/"):
            return JSONResponse(
                {"detail": "Cross-origin request rejected"}, status_code=403
            )
        if (
            not request.url.path.startswith("/api/agent/")
            and request.headers.get("x-donino") != "1"
        ):
            return JSONResponse({"detail": "X-Donino header required"}, status_code=403)
    # Bound the actual body, including requests without Content-Length.
    if request.method in ("POST", "PATCH", "PUT"):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        request._body = bytes(body)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


@app.exception_handler(IntegrityError)
@app.exception_handler(sqlite3.IntegrityError)
async def conflict(request, exc):
    return JSONResponse(
        {"detail": "نام یا پورت تکراری است، یا رکورد مرتبط وجود ندارد."},
        status_code=409,
    )


def admin(request: Request):
    authorization = request.headers.get("authorization", "")
    if authorization:
        if not authorization.startswith("Bearer donino_"):
            raise HTTPException(401, "Invalid API token")
        with database() as db:
            row = db.execute(
                "SELECT a.username,a.role,t.id,t.scopes FROM api_tokens t JOIN admins a USING(username) WHERE t.digest=? AND t.expires>?",
                (digest(authorization[7:]), int(time.time())),
            ).fetchone()
            if not row:
                raise HTTPException(401, "Invalid API token")
            path = request.url.path
            resource = next(
                (
                    r
                    for r in ("users", "nodes", "inbounds", "audit")
                    if path == "/api/" + r or path.startswith("/api/" + r + "/")
                ),
                None,
            )
            operation = "read" if request.method == "GET" else "write"
            if resource == "users" and path.endswith("/subscription"):
                operation = "write"
            if path != "/api/me" and (
                not resource
                or resource + ":" + operation not in json.loads(row["scopes"])
            ):
                raise HTTPException(
                    403, "API token scope does not permit this operation"
                )
            db.execute(
                "UPDATE api_tokens SET last_used=? WHERE id=?",
                (int(time.time()), row["id"]),
            )
            return {
                "username": row["username"],
                "role": row["role"],
                "api_token": row["id"],
            }
    token = request.cookies.get("donino_session", "")
    with database() as db:
        row = db.execute(
            "SELECT a.username,a.role FROM sessions s JOIN admins a USING(username) "
            "WHERE s.token=? AND s.expires>?",
            (digest(token), int(time.time())),
        ).fetchone()
    if not row:
        raise HTTPException(401, "ورود لازم است")
    return dict(row)


def writer(account=Depends(admin)):
    if account["role"] not in ("owner", "operator"):
        raise HTTPException(403, "دسترسی نوشتن ندارید")
    return account


def owner(account=Depends(admin)):
    if account["role"] != "owner":
        raise HTTPException(403, "دسترسی مالک لازم است")
    return account


def node_auth(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Node token required")
    with database() as db:
        node = db.execute(
            "SELECT * FROM nodes WHERE token=? AND enabled=1", (digest(auth[7:]),)
        ).fetchone()
    if not node:
        raise HTTPException(401, "Invalid node token")
    return dict(node)


def one(db, table, record_id):
    # Table names are internal constants only.
    row = db.execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone()
    if not row:
        raise HTTPException(404, "رکورد پیدا نشد")
    return row


def public_user(row, include_secret=False):
    value = dict(row)
    value.pop("credential", None)
    value["status"] = status(value)
    if not include_secret:
        value.pop("token", None)
    return value


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(default="", max_length=6)
    recovery_code: str = Field(default="", max_length=32)


class UserInput(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[\w .@+-]+$")
    enabled: bool = True
    quota: int = Field(default=0, ge=0, le=9_000_000_000_000_000)
    expires: int | None = Field(default=None, gt=0, le=32_503_680_000)
    validity_seconds: int = Field(default=0, ge=0, le=315_360_000)


class NodeInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(
                r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value
            ):
                raise ValueError("Host must be an IP or domain, without scheme or port")
        return value


class InboundInput(BaseModel):
    node_id: str
    name: str = Field(min_length=1, max_length=80)
    protocol: str = Field(pattern=r"^(vless|vmess|trojan)$")
    port: int = Field(ge=1, le=65535)
    sni: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    target: str = Field(
        default="www.microsoft.com:443",
        max_length=260,
        pattern=r"^[A-Za-z0-9.-]+:[0-9]{1,5}$",
    )
    path: str = Field(default="/donino", max_length=200, pattern=r"^/[^\s?#]*$")
    cert_file: str = Field(default="", max_length=500)
    key_file: str = Field(default="", max_length=500)
    enabled: bool = True

    @model_validator(mode="after")
    def valid_settings(self):
        if self.port == 10085:
            raise ValueError("10085 is reserved for local statistics")
        if self.protocol != "vless" and (
            not self.cert_file.startswith("/") or not self.key_file.startswith("/")
        ):
            raise ValueError("TLS needs absolute certificate and key paths on the node")
        if not 1 <= int(self.target.rsplit(":", 1)[1]) <= 65535:
            raise ValueError("Invalid REALITY target port")
        return self


class Usage(BaseModel):
    user_id: str
    period_id: str = Field(default="", max_length=64)
    up: int = Field(ge=0, le=9_000_000_000_000_000)
    down: int = Field(ge=0, le=9_000_000_000_000_000)


class Heartbeat(BaseModel):
    epoch: str = Field(min_length=1, max_length=64)
    applied_revision: str = Field(default="", max_length=64)
    error: str = Field(default="", max_length=500)
    usage: list[Usage] = Field(default_factory=list, max_length=10000)
    agent_version: str = Field(default="", max_length=40)
    core_running: bool | None = None
    apply_mode: str = Field(default="", pattern=r"^(|hot|restart|rollback)$")
    pending_usage: int = Field(default=0, ge=0, le=100000000)

    @model_validator(mode="after")
    def unique_users(self):
        if len({u.user_id for u in self.usage}) != len(self.usage):
            raise ValueError("Duplicate usage user")
        return self


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def health():
    return {"status": "ok", "version": __version__}


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    address = request.client.host if request.client else "unknown"
    now = int(time.time())
    with database() as db:
        db.lock("login:" + address)
        attempts = db.execute(
            "SELECT * FROM login_attempts WHERE address=?", (address,)
        ).fetchone()
        if attempts and attempts["until"] > now and attempts["attempts"] >= 10:
            raise HTTPException(429, "تلاش‌های زیاد؛ ۱۵ دقیقه دیگر دوباره امتحان کنید")
        row = db.execute(
            "SELECT * FROM admins WHERE username=?", (body.username,)
        ).fetchone()
        # Use a fixed dummy hash to avoid a fast unknown-user path.
        dummy = "donino-dummy:" + "0" * 64
        valid = verify_password(body.password, row["password"] if row else dummy)
        if valid and row:
            valid = verify_factor(db, row["username"], body.code, body.recovery_code)
        if not row or not valid:
            count = (
                attempts["attempts"] + 1 if attempts and attempts["until"] > now else 1
            )
            db.execute(
                "INSERT INTO login_attempts VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET attempts=excluded.attempts,until=excluded.until",
                (address, count, now + 900),
            )
            # Commit failed attempts before returning an HTTP error.
            return JSONResponse(
                {"detail": "نام کاربری یا رمز عبور اشتباه است"}, status_code=401
            )
        db.execute("DELETE FROM login_attempts WHERE address=?", (address,))
        db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        token = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?)",
            (digest(token), row["username"], now + 43200),
        )
        audit(db, row["username"], "login")
    response.set_cookie(
        "donino_session",
        token,
        httponly=True,
        samesite="strict",
        max_age=43200,
        secure=os.environ.get("DONINO_SECURE_COOKIE", "true").lower() != "false",
    )
    return {"username": row["username"], "role": row["role"]}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    with database() as db:
        db.execute(
            "DELETE FROM sessions WHERE token=?",
            (digest(request.cookies.get("donino_session", "")),),
        )
    response.delete_cookie("donino_session")
    return {"ok": True}


@app.get("/api/me")
def me(account=Depends(admin)):
    return account


@app.get("/api/openapi.json")
def schema(account=Depends(admin)):
    return app.openapi()


@app.get("/api/overview")
def overview(account=Depends(admin)):
    with database() as db:
        users = [public_user(r) for r in db.execute("SELECT * FROM users")]
        nodes = list(
            db.execute("SELECT last_seen,enabled,error,core_running FROM nodes")
        )
        online = sum(node_online(n) for n in nodes)
        return {
            "users": len(users),
            "active": sum(u["status"] == "active" for u in users),
            "used": sum(u["used"] for u in users),
            "nodes": len(nodes),
            "online_nodes": online,
            "inbounds": db.execute(
                "SELECT COUNT(*) FROM inbounds WHERE enabled=1"
            ).fetchone()[0],
        }


@app.get("/api/users")
def list_users(account=Depends(admin)):
    with database() as db:
        return [
            public_user(r)
            for r in db.execute("SELECT * FROM users ORDER BY created DESC LIMIT 1000")
        ]


@app.post("/api/users", status_code=201)
def add_user(body: UserInput, account=Depends(writer)):
    uid = str(uuid.uuid4())
    with database() as db:
        db.execute(
            "INSERT INTO users(id,credential,name,enabled,quota,expires,token,created) VALUES(?,?,?,?,?,?,?,?)",
            (
                uid,
                str(uuid.uuid4()),
                body.name,
                body.enabled,
                body.quota,
                body.expires,
                secrets.token_urlsafe(32),
                int(time.time()),
            ),
        )
        ensure_identity(db, one(db, "users", uid), owner=account["username"])
        db.execute(
            "UPDATE user_state SET validity_seconds=? WHERE user_id=?",
            (body.validity_seconds, uid),
        )
        audit(db, account["username"], "user.create", uid)
        return public_user(one(db, "users", uid))


@app.put("/api/users/{uid}")
def update_user(uid: str, body: UserInput, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        db.execute(
            "UPDATE users SET name=?,enabled=?,quota=?,expires=? WHERE id=?",
            (body.name, body.enabled, body.quota, body.expires, uid),
        )
        ensure_identity(db, one(db, "users", uid))
        db.execute(
            "UPDATE user_state SET validity_seconds=? WHERE user_id=?",
            (body.validity_seconds, uid),
        )
        audit(db, account["username"], "user.update", uid)
        return public_user(one(db, "users", uid))


@app.delete("/api/users/{uid}")
def delete_user(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        audit(db, account["username"], "user.delete", uid)
    return {"ok": True}


@app.post("/api/users/{uid}/reset-traffic")
def reset_traffic(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        ensure_identity(db, one(db, "users", uid))
        reset_period(db, uid)
        audit(db, account["username"], "user.reset-traffic", uid)
    return {"ok": True}


@app.post("/api/users/{uid}/rotate-subscription")
def rotate_subscription(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        db.execute(
            "UPDATE users SET token=? WHERE id=?", (secrets.token_urlsafe(32), uid)
        )
        audit(db, account["username"], "user.rotate-subscription", uid)
    return {"ok": True}


@app.get("/api/users/{uid}/subscription")
def subscription_info(uid: str, request: Request, account=Depends(writer)):
    with database() as db:
        row = one(db, "users", uid)
        base = public_base(request)
        return {
            "url": base + "/sub/" + row["token"],
            "portal_url": base + "/u/" + row["token"],
            "qr_url": base + "/qr/" + row["token"],
        }


@app.post("/api/users/{uid}/rotate-credentials")
def rotate_credentials(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        db.execute(
            "UPDATE users SET credential=?,token=? WHERE id=?",
            (str(uuid.uuid4()), secrets.token_urlsafe(32), uid),
        )
        # Revoke every downloaded device profile, not only the legacy field.
        for device in db.execute("SELECT id FROM devices WHERE user_id=?", (uid,)):
            for credential in db.execute(
                "SELECT id FROM credentials WHERE device_id=?", (device["id"],)
            ):
                db.execute(
                    "UPDATE credentials SET secret=?,generation=generation+1 WHERE id=?",
                    (str(uuid.uuid4()), credential["id"]),
                )
        audit(db, account["username"], "user.rotate-credentials", uid)
    return {"ok": True}


@app.get("/api/nodes")
def list_nodes(account=Depends(admin)):
    with database() as db:
        result = []
        for row in db.execute("SELECT * FROM nodes"):
            n = dict(row)
            n.pop("token")
            n["online"] = node_online(n)
            result.append(n)
        return result


@app.post("/api/nodes", status_code=201)
def add_node(body: NodeInput, account=Depends(owner)):
    token, nid = secrets.token_urlsafe(48), str(uuid.uuid4())
    with database() as db:
        db.execute(
            "INSERT INTO nodes(id,name,host,token) VALUES(?,?,?,?)",
            (nid, body.name, body.host, digest(token)),
        )
        audit(db, account["username"], "node.create", nid)
    return {"id": nid, "token": token}


@app.delete("/api/nodes/{nid}")
def delete_node(nid: str, account=Depends(owner)):
    with database() as db:
        one(db, "nodes", nid)
        db.execute("DELETE FROM nodes WHERE id=?", (nid,))
        audit(db, account["username"], "node.delete", nid)
    return {"ok": True}


@app.post("/api/nodes/{nid}/rotate-token")
def rotate_node(nid: str, account=Depends(owner)):
    token = secrets.token_urlsafe(48)
    with database() as db:
        one(db, "nodes", nid)
        db.execute("UPDATE nodes SET token=? WHERE id=?", (digest(token), nid))
        audit(db, account["username"], "node.rotate-token", nid)
    return {"token": token}


@app.get("/api/inbounds")
def list_inbounds(account=Depends(admin)):
    with database() as db:
        result = []
        for row in db.execute(
            "SELECT i.*,n.name node_name FROM inbounds i JOIN nodes n ON n.id=i.node_id"
        ):
            value = dict(row)
            s = json.loads(value["settings"])
            s.pop("private_key", None)
            value["settings"] = s
            result.append(value)
        return result


def inbound_settings(body, previous=None):
    settings = body.model_dump(
        exclude={"node_id", "name", "protocol", "port", "enabled"}
    )
    if body.protocol == "vless":
        old = (
            json.loads(previous["settings"])
            if previous and previous["protocol"] == "vless"
            else None
        )
        if old:
            settings.update(
                {key: old[key] for key in ("private_key", "public_key", "short_id")}
            )
        else:
            private = X25519PrivateKey.generate()
            enc = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
            settings.update(
                {
                    "private_key": enc(
                        private.private_bytes(
                            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                        )
                    ),
                    "public_key": enc(
                        private.public_key().public_bytes(
                            Encoding.Raw, PublicFormat.Raw
                        )
                    ),
                    "short_id": secrets.token_hex(8),
                }
            )
    return settings


@app.post("/api/inbounds", status_code=201)
def add_inbound(body: InboundInput, account=Depends(owner)):
    settings = inbound_settings(body)
    iid = str(uuid.uuid4())
    with database() as db:
        one(db, "nodes", body.node_id)
        db.execute(
            "INSERT INTO inbounds(id,node_id,name,protocol,port,settings,enabled) VALUES(?,?,?,?,?,?,?)",
            (
                iid,
                body.node_id,
                body.name,
                body.protocol,
                body.port,
                json.dumps(settings),
                body.enabled,
            ),
        )
        audit(db, account["username"], "inbound.create", iid)
    return {"id": iid}


@app.put("/api/inbounds/{iid}")
def edit_inbound(iid: str, body: InboundInput, account=Depends(owner)):
    with database() as db:
        previous = one(db, "inbounds", iid)
        one(db, "nodes", body.node_id)
        settings = inbound_settings(body, previous)
        db.execute(
            "UPDATE inbounds SET node_id=?,name=?,protocol=?,port=?,settings=?,enabled=? WHERE id=?",
            (
                body.node_id,
                body.name,
                body.protocol,
                body.port,
                json.dumps(settings),
                body.enabled,
                iid,
            ),
        )
        audit(db, account["username"], "inbound.update", iid)
    return {"id": iid}


@app.delete("/api/inbounds/{iid}")
def delete_inbound(iid: str, account=Depends(owner)):
    with database() as db:
        one(db, "inbounds", iid)
        db.execute("DELETE FROM inbounds WHERE id=?", (iid,))
        audit(db, account["username"], "inbound.delete", iid)
    return {"ok": True}


@app.get("/api/agent/config")
def agent_config(node=Depends(node_auth)):
    with database() as db:
        config = compile_config(
            list(
                db.execute(
                    "SELECT * FROM inbounds WHERE node_id=? ORDER BY id", (node["id"],)
                )
            ),
            connection_users(db, node_id=node["id"]),
        )
    return {
        "revision": revision(config),
        "config": config,
        "node_id": node["id"],
        "agent_protocol": 2,
    }


@app.post("/api/agent/heartbeat")
def heartbeat(body: Heartbeat, node=Depends(node_auth)):
    with database() as db:
        db.lock("heartbeat:" + node["id"])
        for sample in body.usage:
            try:
                apply_usage(db, node["id"], body.epoch, sample)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
        db.execute(
            """UPDATE nodes SET last_seen=?,applied_revision=?,error=?,agent_version=?,
            core_running=?,apply_mode=?,pending_usage=? WHERE id=?""",
            (
                int(time.time()),
                body.applied_revision,
                body.error,
                body.agent_version,
                body.core_running,
                body.apply_mode,
                body.pending_usage,
                node["id"],
            ),
        )
    return {"ok": True}


@app.get("/api/audit")
def list_audit(account=Depends(owner)):
    with database() as db:
        return [
            dict(r)
            for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")
        ]


@app.get("/api/backup")
def backup(account=Depends(owner)):
    from .storage import backup_database

    with tempfile.TemporaryDirectory() as folder:
        filename = Path(folder) / "backup"
        kind = backup_database(filename)
        data = filename.read_bytes()
    with database() as db:
        audit(db, account["username"], "backup.download")
    extension = "db" if kind == "sqlite" else "zip"
    return Response(
        data,
        media_type="application/vnd.sqlite3" if kind == "sqlite" else "application/zip",
        headers={
            "Content-Disposition": "attachment; filename=donino-backup." + extension
        },
    )


@app.get("/sub/{token}")
def subscription(token: str, format: str = "base64"):
    if format not in ("base64", "raw", "clash"):
        raise HTTPException(400, "Formats: base64, raw, clash")
    with database() as db:
        user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        if not user or not eligible(user):
            raise HTTPException(404, "Subscription unavailable")
        links, clash = profile_sets(db, user)
        info = f"upload={user['uploaded']}; download={user['downloaded'] + user['legacy_used']}; total={user['quota']}; expire={user['expires'] or 0}"
    headers = {
        "Subscription-Userinfo": info,
        "Profile-Update-Interval": "6",
        "Content-Disposition": "inline; filename=donino-subscription.txt",
    }
    if format == "clash":
        return JSONResponse(clash, headers=headers)
    content = "\n".join(links)
    if format == "base64":
        content = base64.b64encode(content.encode()).decode()
    return Response(content, media_type="text/plain", headers=headers)


def node_online(node):
    return bool(
        node["enabled"]
        and node["last_seen"]
        and node["last_seen"] > time.time() - 30
        and not node["error"]
        and node["core_running"] != 0
    )


def public_base(request):
    return os.environ.get(
        "DONINO_PUBLIC_URL", str(request.base_url).rstrip("/")
    ).rstrip("/")


def portal_user(db, token):
    row = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not row:
        raise HTTPException(404, "Subscription unavailable")
    return row


def portal_profiles(db, user):
    return profile_sets(db, user)


@app.get("/u/{token}")
def portal_page(token: str):
    with database() as db:
        portal_user(db, token)
    return FileResponse(STATIC / "portal.html")


@app.get("/api/portal/{token}")
def portal_info(token: str, request: Request):
    with database() as db:
        user = portal_user(db, token)
        active = eligible(user)
        links, clash = portal_profiles(db, user) if active else ([], {"proxies": []})
        value = {
            key: user[key]
            for key in (
                "name",
                "quota",
                "used",
                "uploaded",
                "downloaded",
                "legacy_used",
                "expires",
            )
        }
        base = public_base(request)
        sub = base + "/sub/" + token
        value.update(
            {
                "status": status(user),
                "remaining": max(0, user["quota"] - user["used"])
                if user["quota"]
                else None,
                "subscription_url": sub if active else None,
                "portal_url": base + "/u/" + token,
                "qr_url": base + "/qr/" + token if active else None,
                "profiles": [
                    {
                        "name": proxy["name"],
                        "protocol": proxy["type"],
                        "uri": link,
                        "qr_url": base + "/qr/" + token + "?profile=" + str(i),
                    }
                    for i, (link, proxy) in enumerate(zip(links, clash["proxies"]))
                ],
            }
        )
        return value


@app.get("/qr/{token}")
def qr_code(
    token: str, request: Request, profile: int | None = None, format: str = "base64"
):
    if format not in ("base64", "clash"):
        raise HTTPException(400, "QR formats: base64, clash")
    with database() as db:
        user = portal_user(db, token)
        if not eligible(user):
            raise HTTPException(404, "Subscription unavailable")
        content = (
            public_base(request)
            + "/sub/"
            + token
            + ("?format=clash" if format == "clash" else "")
        )
        if profile is not None:
            links, _ = portal_profiles(db, user)
            if not 0 <= profile < len(links):
                raise HTTPException(404, "Profile unavailable")
            content = links[profile]
    image = qrcode.make(content, image_factory=SvgPathImage, border=4)
    output = io.BytesIO()
    image.save(output)
    return Response(
        output.getvalue(),
        media_type="image/svg+xml",
        headers={"Content-Disposition": "inline; filename=donino-qr.svg"},
    )


mount_identity_routes(app, admin, writer, owner, one)
