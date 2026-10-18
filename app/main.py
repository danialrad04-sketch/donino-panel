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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
import qrcode
from qrcode.image.svg import SvgPathImage

from . import __version__
from .db import (
    initialize,
    database,
    digest,
    verify_password,
    hash_password,
    audit,
    upsert,
    pg_dump,
    db_path,
    is_postgres,
    IntegrityErrors,
    MAX_DEVICES_PER_USER,
)
from .core import DEFAULT_TRANSPORT, TRANSPORTS, eligible, status, profiles, is_reality
from .secrets import seal
from .accounting import apply_sample, next_period
from .bootstrap import mount_bootstrap
from .network_api import mount_network_api
from .deployments import acknowledge, desired_job
from .engines import XRAY
from .node_api import mount_node_api
from .dns_api import mount_dns_api
from .doctor_api import mount_doctor_api
from .tunnel_api import mount_tunnel_api
from .node_identity import sign_desired
from .budgets import allocations, close_budgets, summaries, reserve_total
from .deps import (
    admin,
    writer,
    owner,
    session_only,
    node_auth,
    one,
    public_base,
)
from .security import (
    PASSWORD_MIN,
    PASSWORD_MAX,
    MAX_TOKENS_PER_ADMIN,
    MAX_TOKEN_DAYS,
    check_second_factor,
    clear_failures,
    guard,
    new_api_token,
    new_recovery_codes,
    new_totp_secret,
    otpauth_uri,
    record_failure,
    revoke_credentials,
    totp_verify,
    is_api_token,
)


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
mount_bootstrap(app)
mount_network_api(app)
mount_node_api(app)
mount_dns_api(app)
mount_doctor_api(app)
mount_tunnel_api(app)


@app.middleware("http")
async def security_headers(request, call_next):
    # Cookie-authenticated mutations require a header unavailable to HTML forms.
    # API-token requests are not ambient browser credentials, so they skip it.
    # No CORS is enabled. Requests carrying a foreign Origin are rejected.
    if request.method in ("POST", "PATCH", "DELETE", "PUT"):
        if request.headers.get("origin") and request.headers["origin"] != str(
            request.base_url
        ).rstrip("/"):
            return JSONResponse(
                {"detail": "Cross-origin request rejected"}, status_code=403
            )
        authorization = request.headers.get("authorization", "")
        bearer = authorization[7:] if authorization.startswith("Bearer ") else ""
        if (
            not request.url.path.startswith("/api/agent/")
            and not (request.url.path == "/dns-query" and bearer.startswith("dns_"))
            and not is_api_token(bearer)
            and request.headers.get("x-donino") != "1"
        ):
            return JSONResponse({"detail": "X-Donino header required"}, status_code=403)
    # Bound the actual body, including requests without Content-Length.
    if request.method in ("POST", "PATCH", "PUT"):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > (4096 if request.url.path == "/dns-query" else 2_000_000):
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


async def conflict(request, exc):
    return JSONResponse(
        {"detail": "نام یا پورت تکراری است، یا رکورد مرتبط وجود ندارد."},
        status_code=409,
    )


for _error_class in IntegrityErrors:
    app.add_exception_handler(_error_class, conflict)


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
    code: str = Field(default="", max_length=32)


class UserInput(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[\w .@+-]+$")
    enabled: bool = True
    quota: int = Field(default=0, ge=0, le=9_000_000_000_000_000)
    expires: int | None = Field(default=None, gt=0, le=32_503_680_000)
    period: str = Field(default="none", pattern=r"^(none|monthly)$")
    period_days: int = Field(default=30, ge=1, le=366)
    quota_mode: str | None = Field(default=None, pattern=r"^(legacy|lease)$")


class DeviceInput(BaseModel):
    name: str = Field(min_length=1, max_length=40, pattern=r"^[\w .@+-]+$")
    enabled: bool = True


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
    transport: str = Field(default="", pattern=r"^(|tcp|ws|grpc)$")
    port: int = Field(ge=1, le=65535)
    sni: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    target: str = Field(
        default="www.microsoft.com:443",
        max_length=260,
        pattern=r"^[A-Za-z0-9.-]+:[0-9]{1,5}$",
    )
    path: str = Field(default="/donino", max_length=200, pattern=r"^/[^\s?#]*$")
    service_name: str = Field(
        default="donino", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"
    )
    cert_file: str = Field(default="", max_length=500)
    key_file: str = Field(default="", max_length=500)
    enabled: bool = True

    @model_validator(mode="after")
    def valid_settings(self):
        if self.port == 10085:
            raise ValueError("10085 is reserved for local statistics")
        self.transport = self.transport or DEFAULT_TRANSPORT[self.protocol]
        if self.transport not in TRANSPORTS[self.protocol]:
            allowed = ", ".join(TRANSPORTS[self.protocol])
            raise ValueError(f"{self.protocol} supports only: {allowed}")
        if not is_reality(self.protocol, self.transport) and (
            not self.cert_file.startswith("/") or not self.key_file.startswith("/")
        ):
            raise ValueError("TLS needs absolute certificate and key paths on the node")
        if not 1 <= int(self.target.rsplit(":", 1)[1]) <= 65535:
            raise ValueError("Invalid REALITY target port")
        return self


class Usage(BaseModel):
    # Xray client id. For devices this is the device id; the default device id
    # equals the user id, so agents from before 0.3 keep working unchanged.
    user_id: str
    period_no: int | None = Field(default=None, ge=0, le=2147483647)
    lease_id: str | None = Field(default=None, min_length=1, max_length=64)
    up: int = Field(ge=0, le=9_000_000_000_000_000)
    down: int = Field(ge=0, le=9_000_000_000_000_000)


class Heartbeat(BaseModel):
    agent_instance: uuid.UUID | None = None
    closed_leases: list[str] = Field(default_factory=list, max_length=10000)
    epoch: str = Field(min_length=1, max_length=64)
    applied_revision: str = Field(default="", max_length=64)
    rejected_revision: str = Field(default="", max_length=64)
    job_id: str = Field(default="", max_length=64)
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


class PasswordChange(BaseModel):
    current: str = Field(min_length=1, max_length=PASSWORD_MAX)
    new: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


class PasswordInput(BaseModel):
    password: str = Field(min_length=1, max_length=PASSWORD_MAX)


class CodeInput(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class PasswordAndCode(BaseModel):
    password: str = Field(min_length=1, max_length=PASSWORD_MAX)
    code: str = Field(min_length=6, max_length=32)


class TokenInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scope: str = Field(pattern=r"^(read|users|full)$")
    days: int = Field(default=30, ge=1, le=MAX_TOKEN_DAYS)


def roll_periods(db, now=None):
    """Reset usage of monthly users whose period has ended.

    Baselines in `counters` are kept, so bytes already billed are never billed again.
    Runs before usage is applied so a new period starts clean.
    """
    now = int(time.time()) if now is None else now
    due = db.execute(
        "SELECT * FROM users WHERE period='monthly' AND period_start IS NOT NULL "
        "AND period_start + period_days*86400 <= ?",
        (now,),
    ).fetchall()
    for user in due:
        next_period(db, user, now, start=now)
    return len(due)


def client_rows(db, where="", args=(), *, node_id=None):
    """Every device credential with its eligibility, for config or profiles."""
    if node_id:
        where += (
            (" AND " if where else "WHERE ")
            + "(u.node_mode='all' OR EXISTS(SELECT 1 FROM user_nodes un WHERE un.user_id=u.id AND un.node_id=?))"
        )
        args = (*args, node_id)
    rows = db.execute(
        "SELECT d.id, d.secret, d.name AS device_name, d.enabled AS device_enabled, "
        "d.user_id, u.name AS user_name, u.enabled, u.quota, u.used, u.expires, u.period_no, u.quota_mode "
        f"FROM devices d JOIN users u ON u.id=d.user_id {where} ORDER BY d.id",
        args,
    ).fetchall()
    return [
        {
            "id": r["id"],
            "secret": r["secret"],
            "device_name": r["device_name"],
            "user_id": r["user_id"],
            "period_no": r["period_no"],
            "quota_mode": r["quota_mode"],
            "eligible": bool(r["device_enabled"]) and eligible(dict(r)),
        }
        for r in rows
    ]


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readiness():
    try:
        with database() as db:
            db.execute("SELECT 1").fetchone()
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ok", "version": __version__}


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    address = request.client.host if request.client else "unknown"
    now = int(time.time())
    with database() as db:
        guard(db, address, now)
        row = db.execute(
            "SELECT * FROM admins WHERE username=?", (body.username,)
        ).fetchone()
        # Use a fixed dummy hash to avoid a fast unknown-user path.
        dummy = "donino-dummy:" + "0" * 64
        valid = verify_password(body.password, row["password"] if row else dummy)
        if not row or not valid:
            record_failure(db, address, now)
            # Commit failed attempts before returning an HTTP error.
            return JSONResponse(
                {"detail": "نام کاربری یا رمز عبور اشتباه است"}, status_code=401
            )
        mfa = db.execute(
            "SELECT * FROM admin_mfa WHERE username=? AND enabled=1",
            (row["username"],),
        ).fetchone()
        if mfa:
            if not body.code:
                return JSONResponse({"mfa_required": True}, status_code=202)
            if not check_second_factor(db, mfa, body.code):
                record_failure(db, address, now)
                return JSONResponse(
                    {"detail": "کد دو مرحله‌ای یا کد بازیابی درست نیست"},
                    status_code=401,
                )
        clear_failures(db, address)
        db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        token = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO sessions(token,username,expires,sid,created,address,agent) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                digest(token),
                row["username"],
                now + 43200,
                secrets.token_hex(8),
                now,
                address[:64],
                request.headers.get("user-agent", "")[:200],
            ),
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
    return {"username": row["username"], "role": row["role"], "mfa": bool(mfa)}


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
    return {
        "username": account["username"],
        "role": account["role"],
        "scope": account["scope"],
        "via": account["via"],
    }


@app.get("/api/openapi.json")
def schema(account=Depends(admin)):
    return app.openapi()


# ---------- account security: 2FA, sessions, API tokens, password ----------


@app.get("/api/account")
def account_info(account=Depends(admin)):
    with database() as db:
        mfa = db.execute(
            "SELECT enabled FROM admin_mfa WHERE username=?", (account["username"],)
        ).fetchone()
        sessions = db.execute(
            "SELECT sid,created,expires,address,agent FROM sessions "
            "WHERE username=? AND expires>? ORDER BY created DESC",
            (account["username"], int(time.time())),
        ).fetchall()
        tokens = db.execute(
            "SELECT id,name,scope,expires,created,last_used FROM api_tokens "
            "WHERE username=? ORDER BY created DESC",
            (account["username"],),
        ).fetchall()
    current = account.get("sid")
    return {
        "username": account["username"],
        "role": account["role"],
        "mfa_enabled": bool(mfa and mfa["enabled"]),
        "sessions": [{**dict(s), "current": s["sid"] == current} for s in sessions],
        "tokens": [dict(t) for t in tokens],
    }


@app.post("/api/account/mfa/setup")
def mfa_setup(body: PasswordInput, account=Depends(session_only)):
    secret = new_totp_secret()
    with database() as db:
        key = "security:" + account["username"]
        guard(db, key)
        row = db.execute(
            "SELECT password FROM admins WHERE username=?", (account["username"],)
        ).fetchone()
        if not row or not verify_password(body.password, row["password"]):
            record_failure(db, key)
            return JSONResponse({"detail": "رمز عبور درست نیست"}, status_code=401)
        clear_failures(db, key)
        existing = db.execute(
            "SELECT enabled FROM admin_mfa WHERE username=?", (account["username"],)
        ).fetchone()
        if existing and existing["enabled"]:
            raise HTTPException(409, "کد دو مرحله‌ای فعال است؛ اول آن را غیرفعال کنید")
        upsert(
            db,
            "admin_mfa",
            ["username", "secret", "enabled", "last_step", "recovery", "created"],
            [account["username"], seal(secret), 0, 0, "[]", int(time.time())],
            ["username"],
        )
    return {"secret": secret, "otpauth": otpauth_uri(secret, account["username"])}


@app.post("/api/account/mfa/enable")
def mfa_enable(body: CodeInput, account=Depends(session_only)):
    with database() as db:
        key = "security:" + account["username"]
        guard(db, key)
        mfa = db.execute(
            "SELECT * FROM admin_mfa WHERE username=? AND enabled=0",
            (account["username"],),
        ).fetchone()
        if not mfa:
            raise HTTPException(404, "ابتدا راه‌اندازی کد دو مرحله‌ای را شروع کنید")
        step = totp_verify(mfa["secret"], body.code)
        if step is None:
            record_failure(db, key)
            return JSONResponse({"detail": "کد وارد‌شده درست نیست"}, status_code=401)
        clear_failures(db, key)
        codes, hashes = new_recovery_codes()
        db.execute(
            "UPDATE admin_mfa SET enabled=1,last_step=?,recovery=? WHERE username=?",
            (step, json.dumps(hashes), account["username"]),
        )
        audit(db, account["username"], "mfa.enable")
        revoke_credentials(db, account["username"], keep_session=account["session"])
    # Recovery codes are shown exactly once; only their digests are stored.
    return {"recovery_codes": codes}


@app.post("/api/account/mfa/disable")
def mfa_disable(body: PasswordAndCode, account=Depends(session_only)):
    with database() as db:
        key = "security:" + account["username"]
        guard(db, key)
        row = db.execute(
            "SELECT password FROM admins WHERE username=?", (account["username"],)
        ).fetchone()
        mfa = db.execute(
            "SELECT * FROM admin_mfa WHERE username=? AND enabled=1",
            (account["username"],),
        ).fetchone()
        if not mfa or not verify_password(body.password, row["password"]):
            record_failure(db, key)
            return JSONResponse(
                {"detail": "رمز عبور یا کد دو مرحله‌ای درست نیست"}, status_code=401
            )
        if not check_second_factor(db, mfa, body.code):
            record_failure(db, key)
            return JSONResponse(
                {"detail": "رمز عبور یا کد دو مرحله‌ای درست نیست"}, status_code=401
            )
        clear_failures(db, key)
        db.execute("DELETE FROM admin_mfa WHERE username=?", (account["username"],))
        audit(db, account["username"], "mfa.disable")
        revoke_credentials(db, account["username"], keep_session=account["session"])
    return {"ok": True}


@app.post("/api/account/password")
def change_password(body: PasswordChange, account=Depends(session_only)):
    with database() as db:
        row = db.execute(
            "SELECT password FROM admins WHERE username=?", (account["username"],)
        ).fetchone()
        if not verify_password(body.current, row["password"]):
            raise HTTPException(401, "رمز فعلی درست نیست")
        db.execute(
            "UPDATE admins SET password=? WHERE username=?",
            (hash_password(body.new), account["username"]),
        )
        # Other sessions and every API token of this admin stop working at once.
        revoke_credentials(
            db, account["username"], keep_session=account["session"], tokens=True
        )
        audit(db, account["username"], "account.password")
    return {"ok": True}


@app.delete("/api/account/sessions/{sid}")
def revoke_session(sid: str, account=Depends(session_only)):
    with database() as db:
        cursor = db.execute(
            "DELETE FROM sessions WHERE sid=? AND username=?",
            (sid, account["username"]),
        )
        if not cursor.rowcount:
            raise HTTPException(404, "نشست پیدا نشد")
        audit(db, account["username"], "session.revoke", sid)
    return {"ok": True}


@app.post("/api/account/sessions/revoke-others")
def revoke_other_sessions(account=Depends(session_only)):
    with database() as db:
        revoke_credentials(
            db, account["username"], keep_session=account["session"], tokens=False
        )
        audit(db, account["username"], "session.revoke-others")
    return {"ok": True}


@app.post("/api/account/tokens", status_code=201)
def create_token(body: TokenInput, account=Depends(session_only)):
    token = new_api_token()
    token_id = str(uuid.uuid4())
    now = int(time.time())
    with database() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM api_tokens WHERE username=? AND expires>?",
            (account["username"], now),
        ).fetchone()[0]
        if count >= MAX_TOKENS_PER_ADMIN:
            raise HTTPException(409, "تعداد توکن‌های فعال به حد مجاز رسیده است")
        db.execute(
            "INSERT INTO api_tokens(id,username,name,digest,scope,expires,created) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                token_id,
                account["username"],
                body.name,
                digest(token),
                body.scope,
                now + body.days * 86400,
                now,
            ),
        )
        audit(db, account["username"], "token.create", token_id)
    # The plain token is returned once; only its digest is stored.
    return {"id": token_id, "token": token, "scope": body.scope}


@app.delete("/api/account/tokens/{token_id}")
def revoke_token(token_id: str, account=Depends(session_only)):
    with database() as db:
        cursor = db.execute(
            "DELETE FROM api_tokens WHERE id=? AND username=?",
            (token_id, account["username"]),
        )
        if not cursor.rowcount:
            raise HTTPException(404, "توکن پیدا نشد")
        audit(db, account["username"], "token.revoke", token_id)
    return {"ok": True}


# ---------- administrators (owner only; session login required) ----------


class AdminInput(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    role: str = Field(pattern=r"^(owner|operator|viewer)$")


class AdminRoleInput(BaseModel):
    role: str = Field(pattern=r"^(owner|operator|viewer)$")


class AdminPasswordInput(BaseModel):
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


def owner_count(db, exclude=None):
    return db.execute(
        "SELECT COUNT(*) FROM admins WHERE role='owner' AND username<>?",
        (exclude or "",),
    ).fetchone()[0]


@app.get("/api/admins")
def list_admins(account=Depends(owner)):
    with database() as db:
        return [
            {
                "username": r["username"],
                "role": r["role"],
                "mfa_enabled": bool(r["mfa"]),
            }
            for r in db.execute(
                "SELECT a.username,a.role,COALESCE(m.enabled,0) AS mfa FROM admins a "
                "LEFT JOIN admin_mfa m ON m.username=a.username ORDER BY a.username"
            )
        ]


@app.post("/api/admins", status_code=201)
def create_admin(
    body: AdminInput, account=Depends(owner), session=Depends(session_only)
):
    with database() as db:
        if db.execute(
            "SELECT 1 FROM admins WHERE username=?", (body.username,)
        ).fetchone():
            raise HTTPException(409, "این نام کاربری از قبل وجود دارد")
        db.execute(
            "INSERT INTO admins(username,password,role) VALUES(?,?,?)",
            (body.username, hash_password(body.password), body.role),
        )
        audit(db, account["username"], "admin.create", body.username)
    return {"username": body.username, "role": body.role}


@app.put("/api/admins/{username}")
def change_admin_role(
    username: str,
    body: AdminRoleInput,
    account=Depends(owner),
    session=Depends(session_only),
):
    with database() as db:
        row = db.execute(
            "SELECT * FROM admins WHERE username=?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "مدیر پیدا نشد")
        if (
            row["role"] == "owner"
            and body.role != "owner"
            and owner_count(db, username) == 0
        ):
            raise HTTPException(409, "حداقل یک مالک باید باقی بماند")
        db.execute("UPDATE admins SET role=? WHERE username=?", (body.role, username))
        if row["role"] != body.role:
            # The admin's permissions changed: end their sessions and tokens.
            revoke_credentials(db, username, tokens=True)
        audit(db, account["username"], "admin.role", f"{username}:{body.role}")
    return {"username": username, "role": body.role}


@app.post("/api/admins/{username}/password")
def reset_admin_password(
    username: str,
    body: AdminPasswordInput,
    account=Depends(owner),
    session=Depends(session_only),
):
    with database() as db:
        if not db.execute(
            "SELECT 1 FROM admins WHERE username=?", (username,)
        ).fetchone():
            raise HTTPException(404, "مدیر پیدا نشد")
        db.execute(
            "UPDATE admins SET password=? WHERE username=?",
            (hash_password(body.password), username),
        )
        revoke_credentials(db, username, tokens=True)
        audit(db, account["username"], "admin.password", username)
    return {"ok": True}


@app.delete("/api/admins/{username}")
def delete_admin(username: str, account=Depends(owner), session=Depends(session_only)):
    if username == account["username"]:
        raise HTTPException(409, "حساب خودتان را نمی‌توانید حذف کنید")
    with database() as db:
        row = db.execute(
            "SELECT role FROM admins WHERE username=?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "مدیر پیدا نشد")
        if row["role"] == "owner" and owner_count(db, username) == 0:
            raise HTTPException(409, "حداقل یک مالک باید باقی بماند")
        db.execute("DELETE FROM admins WHERE username=?", (username,))
        audit(db, account["username"], "admin.delete", username)
    return {"ok": True}


# ---------- overview, users, devices ----------


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


def escape_like(text):
    return text.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def state_filter(state, now):
    # Mirrors core.status(): disabled, then expired, then limited, else active.
    return {
        "disabled": ("enabled=0", []),
        "expired": ("enabled=1 AND expires IS NOT NULL AND expires<=?", [now]),
        "limited": (
            "enabled=1 AND (expires IS NULL OR expires>?) AND quota>0 AND used>=quota",
            [now],
        ),
        "active": (
            "enabled=1 AND (expires IS NULL OR expires>?) AND (quota=0 OR used<quota)",
            [now],
        ),
    }[state]


@app.get("/api/users")
def list_users(
    response: Response,
    limit: int | None = Query(None, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000_000),
    q: str = Query("", max_length=80),
    state: str = Query("", pattern=r"^(|active|disabled|expired|limited)$"),
    account=Depends(admin),
):
    """Without `limit` the legacy response is kept: the 1000 newest users."""
    now = int(time.time())
    clauses, args = [], []
    if q:
        clauses.append("name LIKE ? ESCAPE '!'")
        args.append("%" + escape_like(q) + "%")
    if state:
        clause, extra = state_filter(state, now)
        clauses.append(clause)
        args.extend(extra)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with database() as db:
        budget_values = summaries(db)

        def render_user(row):
            value = dict(row)
            value.update(
                budget_values.get(
                    (value["id"], value["period_no"]),
                    {"budget_reserved": 0, "budget_unreconciled": 0},
                )
            )
            return public_user(value)

        if limit is None:
            rows = db.execute(
                f"SELECT * FROM users{where} ORDER BY created DESC LIMIT 1000", args
            )
            return [render_user(r) for r in rows]
        total = db.execute(f"SELECT COUNT(*) FROM users{where}", args).fetchone()[0]
        rows = db.execute(
            f"SELECT * FROM users{where} ORDER BY created DESC, id LIMIT ? OFFSET ?",
            [*args, limit, offset],
        )
        response.headers["X-Total-Count"] = str(total)
        return [render_user(r) for r in rows]


@app.post("/api/users", status_code=201)
def add_user(body: UserInput, account=Depends(writer)):
    if body.quota_mode == "lease" and body.quota <= 0:
        raise HTTPException(422, "حالت بودجهٔ اشتراکی به سهمیهٔ مثبت نیاز دارد")
    uid = str(uuid.uuid4())
    credential = str(uuid.uuid4())
    now = int(time.time())
    with database() as db:
        db.execute(
            "INSERT INTO users(id,credential,name,enabled,quota,expires,token,created,period,period_days,quota_mode) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                uid,
                credential,
                body.name,
                body.enabled,
                body.quota,
                body.expires,
                secrets.token_urlsafe(32),
                now,
                body.period,
                body.period_days,
                body.quota_mode or "legacy",
            ),
        )
        # Every user starts with one default device whose id is the user id.
        db.execute(
            "INSERT INTO devices(id,user_id,name,secret,enabled,is_default,created) "
            "VALUES(?,?,?,?,1,1,?)",
            (uid, uid, "default", credential, now),
        )
        audit(db, account["username"], "user.create", uid)
        return public_user(one(db, "users", uid))


@app.put("/api/users/{uid}")
def update_user(uid: str, body: UserInput, account=Depends(writer)):
    with database() as db:
        previous = one(db, "users", uid)
        if (
            body.enabled
            and db.execute(
                "SELECT 1 FROM doctor_import_users WHERE user_id=?", (uid,)
            ).fetchone()
        ):
            raise HTTPException(
                409,
                "این حساب در مرحلهٔ انتقال doctor-dns است؛ تا تطبیق خدمت و حجم، فعال‌سازی آن پشتیبانی نمی‌شود",
            )
        if body.quota_mode is not None and body.quota_mode != previous["quota_mode"]:
            raise HTTPException(
                409,
                "حالت سهمیه فقط هنگام ساخت کاربر انتخاب می‌شود؛ برای مهاجرت، کاربر جدید بسازید",
            )
        if previous["quota_mode"] == "lease" and body.quota <= 0:
            raise HTTPException(422, "حالت بودجهٔ اشتراکی به سهمیهٔ مثبت نیاز دارد")
        if (
            previous["quota_mode"] == "lease"
            and body.quota < previous["quota"]
            and body.quota
            < previous["used"] + reserve_total(db, uid, previous["period_no"])
        ):
            raise HTTPException(
                409,
                "سهمیه از مصرف و بودجهٔ تخصیص‌یافته کمتر است؛ ابتدا بودجه‌های فعال را تسویه کنید",
            )
        # Switching the period restarts the cycle at the next usage.
        period_start = previous["period_start"]
        if (
            body.period != previous["period"]
            or body.period_days != previous["period_days"]
        ):
            period_start = None
        if body.period == "none":
            period_start = None
        db.execute(
            "UPDATE users SET name=?,enabled=?,quota=?,expires=?,period=?,period_days=?,period_start=? WHERE id=?",
            (
                body.name,
                body.enabled,
                body.quota,
                body.expires,
                body.period,
                body.period_days,
                period_start,
                uid,
            ),
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
        user = one(db, "users", uid)
        next_period(db, user, int(time.time()))
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
        credential = str(uuid.uuid4())
        db.execute(
            "UPDATE users SET credential=?,token=? WHERE id=?",
            (credential, secrets.token_urlsafe(32), uid),
        )
        db.execute(
            "UPDATE devices SET secret=? WHERE user_id=? AND is_default=1",
            (credential, uid),
        )
        for device in db.execute(
            "SELECT id FROM devices WHERE user_id=? AND is_default=0", (uid,)
        ).fetchall():
            db.execute(
                "UPDATE devices SET secret=? WHERE id=?",
                (str(uuid.uuid4()), device["id"]),
            )
        audit(db, account["username"], "user.rotate-credentials", uid)
    return {"ok": True}


def device_public(row):
    value = dict(row)
    value.pop("secret", None)
    value.pop("token", None)
    return value


@app.get("/api/users/{uid}/devices")
def list_devices(uid: str, account=Depends(admin)):
    with database() as db:
        one(db, "users", uid)
        rows = db.execute(
            "SELECT id,user_id,name,enabled,is_default,uploaded,downloaded,created "
            "FROM devices WHERE user_id=? ORDER BY created, id",
            (uid,),
        ).fetchall()
        return [dict(r) for r in rows]


@app.post("/api/users/{uid}/devices", status_code=201)
def add_device(uid: str, body: DeviceInput, account=Depends(writer)):
    with database() as db:
        one(db, "users", uid)
        count = db.execute(
            "SELECT COUNT(*) FROM devices WHERE user_id=?", (uid,)
        ).fetchone()[0]
        if count >= MAX_DEVICES_PER_USER:
            raise HTTPException(409, "تعداد دستگاه‌های این کاربر به حد مجاز رسیده است")
        did = str(uuid.uuid4())
        db.execute(
            "INSERT INTO devices(id,user_id,name,secret,enabled,is_default,created) "
            "VALUES(?,?,?,?,?,0,?)",
            (did, uid, body.name, str(uuid.uuid4()), body.enabled, int(time.time())),
        )
        audit(db, account["username"], "device.create", did)
        return device_public(one(db, "devices", did))


@app.put("/api/devices/{did}")
def update_device(did: str, body: DeviceInput, account=Depends(writer)):
    with database() as db:
        one(db, "devices", did)
        db.execute(
            "UPDATE devices SET name=?,enabled=? WHERE id=?",
            (body.name, body.enabled, did),
        )
        audit(db, account["username"], "device.update", did)
        return device_public(one(db, "devices", did))


@app.delete("/api/devices/{did}")
def delete_device(did: str, account=Depends(writer)):
    with database() as db:
        device = one(db, "devices", did)
        if device["is_default"]:
            raise HTTPException(
                409, "دستگاه پیش‌فرض قابل حذف نیست؛ می‌توانید آن را غیرفعال کنید"
            )
        db.execute("DELETE FROM devices WHERE id=?", (did,))
        audit(db, account["username"], "device.delete", did)
    return {"ok": True}


@app.post("/api/devices/{did}/rotate-secret")
def rotate_device(did: str, account=Depends(writer)):
    with database() as db:
        one(db, "devices", did)
        db.execute("UPDATE devices SET secret=? WHERE id=?", (str(uuid.uuid4()), did))
        audit(db, account["username"], "device.rotate-secret", did)
    return {"ok": True}


# ---------- nodes and inbounds ----------


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
        if db.execute(
            "SELECT 1 FROM budget_leases b JOIN users u ON u.id=b.user_id AND u.period_no=b.period_no WHERE b.node_id=? AND b.closed=0 AND b.granted>b.spent LIMIT 1",
            (nid,),
        ).fetchone():
            raise HTTPException(
                409,
                "نود بودجهٔ مصرف تسویه‌نشده دارد؛ حذف آن ذخیرهٔ نامعلوم را آزاد نمی‌کند",
            )
        db.execute("DELETE FROM nodes WHERE id=?", (nid,))
        audit(db, account["username"], "node.delete", nid)
    return {"ok": True}


@app.post("/api/nodes/{nid}/rotate-token")
def rotate_node(nid: str, account=Depends(owner)):
    token = secrets.token_urlsafe(48)
    with database() as db:
        node = one(db, "nodes", nid)
        if node["auth_mode"] == "mtls":
            raise HTTPException(
                409,
                "این نود از گواهی استفاده می‌کند؛ ثبت امن یا ابطال گواهی را انتخاب کنید",
            )
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
    if is_reality(body.protocol, body.transport):
        old = (
            json.loads(previous["settings"])
            if previous and previous["protocol"] == "vless"
            else {}
        )
        if old.get("private_key"):
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


# ---------- agent ----------


@app.get("/api/agent/config")
def agent_config(instance: uuid.UUID | None = None, node=Depends(node_auth)):
    with database() as db:
        roll_periods(db)
        clients = client_rows(db, node_id=node["id"])
        budget_grants = allocations(
            db, node, clients, str(instance) if instance else ""
        )
        config = XRAY.compile(
            list(
                db.execute(
                    "SELECT * FROM inbounds WHERE node_id=? ORDER BY id", (node["id"],)
                )
            ),
            clients,
        )
        periods = {client["id"]: client["period_no"] for client in clients}
        job_id, checksum = desired_job(db, node["id"], config, periods)
        previous_sequence = db.execute(
            "SELECT config_sequence FROM nodes WHERE id=?", (node["id"],)
        ).fetchone()[0]
        sequence = max(previous_sequence + 1, time.time_ns() // 1_000_000)
        db.execute(
            "UPDATE nodes SET config_sequence=? WHERE id=?", (sequence, node["id"])
        )
    return sign_desired(
        {
            "revision": checksum,
            "job_id": job_id,
            "config": config,
            "periods": periods,
            "node_id": node["id"],
            "agent_protocol": 6,
            "agent_instance": str(instance) if instance else "",
            "budgets": budget_grants,
        },
        sequence=sequence,
    )


@app.post("/api/agent/heartbeat")
def heartbeat(body: Heartbeat, node=Depends(node_auth)):
    with database() as db:
        now = int(time.time())
        roll_periods(db, now)
        for sample in body.usage:
            apply_sample(db, node["id"], body.epoch, sample, now)
        if body.closed_leases:
            if body.core_running is not False or body.pending_usage or body.usage:
                raise HTTPException(
                    409,
                    "Stop the engine and acknowledge all samples before closing budgets",
                )
            close_budgets(
                db,
                node,
                str(body.agent_instance) if body.agent_instance else "",
                body.closed_leases,
                now,
            )
        acknowledge(db, node["id"], body, now)
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
    # Back up without holding a write transaction on the source connection.
    with tempfile.TemporaryDirectory() as folder:
        if is_postgres():
            filename = Path(folder) / "backup.dump"
            try:
                pg_dump(filename)
            except RuntimeError as error:
                raise HTTPException(503, str(error))
            media, download = "application/octet-stream", "donino-backup.dump"
        else:
            filename = Path(folder) / "backup.db"
            source = sqlite3.connect(db_path())
            target = sqlite3.connect(filename)
            try:
                source.backup(target)
            finally:
                source.close()
                target.close()
            media, download = "application/vnd.sqlite3", "donino-backup.db"
        data = filename.read_bytes()
    with database() as db:
        audit(db, account["username"], "backup.download")
    return Response(
        data,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename={download}"},
    )


# ---------- subscriptions and customer portal ----------


def node_online(node):
    return bool(
        node["enabled"]
        and node["last_seen"]
        and node["last_seen"] > time.time() - 30
        and not node["error"]
        and node["core_running"] != 0
    )


def inbound_rows(db):
    return list(
        db.execute(
            "SELECT i.*,n.host,n.name node_name,n.enabled node_enabled "
            "FROM inbounds i JOIN nodes n ON n.id=i.node_id ORDER BY i.id"
        )
    )


def user_profiles(db, user):
    clients = client_rows(db, "WHERE d.user_id=?", (user["id"],))
    inbounds = inbound_rows(db)
    if user["quota_mode"] == "lease":
        secure_nodes = {
            row[0]
            for row in db.execute(
                "SELECT id FROM nodes WHERE enabled=1 AND auth_mode='mtls'"
            )
        }
        inbounds = [row for row in inbounds if row["node_id"] in secure_nodes]
    if user["node_mode"] == "selected":
        allowed = {
            row[0]
            for row in db.execute(
                "SELECT node_id FROM user_nodes WHERE user_id=?", (user["id"],)
            )
        }
        inbounds = [row for row in inbounds if row["node_id"] in allowed]
    from .tunnel_endpoints import subscription_rows

    return profiles(clients, subscription_rows(db, inbounds))


@app.get("/sub/{token}")
def subscription(token: str, format: str = "base64"):
    if format not in ("base64", "raw", "clash"):
        raise HTTPException(400, "Formats: base64, raw, clash")
    with database() as db:
        roll_periods(db)
        user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        if not user or not eligible(user):
            raise HTTPException(404, "Subscription unavailable")
        links, clash = user_profiles(db, user)
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


def portal_user(db, token):
    row = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not row:
        raise HTTPException(404, "Subscription unavailable")
    return row


@app.get("/u/{token}")
def portal_page(token: str):
    with database() as db:
        portal_user(db, token)
    return FileResponse(STATIC / "portal.html")


@app.get("/api/portal/{token}")
def portal_info(token: str, request: Request):
    with database() as db:
        roll_periods(db)
        user = portal_user(db, token)
        active = eligible(user)
        links, clash = user_profiles(db, user) if active else ([], {"proxies": []})
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
        value["quota_mode"] = user["quota_mode"]
        value.update(
            summaries(db).get(
                (user["id"], user["period_no"]),
                {"budget_reserved": 0, "budget_unreconciled": 0},
            )
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
            links, _ = user_profiles(db, user)
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
