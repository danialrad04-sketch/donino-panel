"""Shared FastAPI dependencies: administrator, API-token and node authentication."""

import os
import time

from fastapi import Depends, HTTPException, Request

from .db import database, digest
from .security import is_api_token

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def authenticate(request: Request):
    """Resolve the caller from an API token (preferred) or the session cookie.

    API tokens never fall back to the cookie: an invalid `dnk_` token is a 401
    even if a valid session cookie is present.
    """
    now = int(time.time())
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and is_api_token(auth[7:]):
        with database() as db:
            row = db.execute(
                "SELECT t.id,t.scope,t.last_used,a.username,a.role FROM api_tokens t "
                "JOIN admins a ON a.username=t.username WHERE t.digest=? AND t.expires>?",
                (digest(auth[7:]), now),
            ).fetchone()
            if row and (not row["last_used"] or row["last_used"] < now - 60):
                db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (now, row["id"]))
        if not row:
            raise HTTPException(401, "توکن نامعتبر یا منقضی است")
        return {
            "username": row["username"],
            "role": row["role"],
            "scope": row["scope"],
            "via": "token",
            "token_id": row["id"],
        }
    cookie = digest(request.cookies.get("donino_session", ""))
    with database() as db:
        row = db.execute(
            "SELECT a.username,a.role,s.sid FROM sessions s "
            "JOIN admins a ON a.username=s.username WHERE s.token=? AND s.expires>?",
            (cookie, now),
        ).fetchone()
    if not row:
        raise HTTPException(401, "ورود لازم است")
    return {
        "username": row["username"],
        "role": row["role"],
        "scope": "full",
        "via": "session",
        "sid": row["sid"],
        "session": cookie,
    }


def admin(request: Request):
    account = authenticate(request)
    if account["scope"] == "read" and request.method not in SAFE_METHODS:
        raise HTTPException(403, "این توکن فقط دسترسی خواندن دارد")
    return account


def writer(account=Depends(admin)):
    if account["role"] not in ("owner", "operator") or account["scope"] == "read":
        raise HTTPException(403, "دسترسی نوشتن ندارید")
    return account


def owner(account=Depends(admin)):
    if account["role"] != "owner":
        raise HTTPException(403, "دسترسی مالک لازم است")
    if account["scope"] != "full":
        raise HTTPException(403, "دامنهٔ این توکن برای عملیات مالک کافی نیست")
    return account


def session_only(account=Depends(admin)):
    """Account-security endpoints cannot be driven by API tokens."""
    if account["via"] != "session":
        raise HTTPException(403, "این عملیات فقط با ورود به پنل ممکن است")
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


def public_base(request):
    return os.environ.get(
        "DONINO_PUBLIC_URL", str(request.base_url).rstrip("/")
    ).rstrip("/")
