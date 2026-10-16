"""One-use, expiring first-owner setup. No shared or default password."""

import hmac
import os
import time

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .db import audit, database, digest, hash_password


class BootstrapInput(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    username: str = Field(min_length=1, max_length=64, pattern=r"^[\w.@+-]+$")
    password: str = Field(min_length=12, max_length=256)


def mount_bootstrap(app):
    @app.post("/api/bootstrap", status_code=201)
    def bootstrap(body: BootstrapInput, request: Request):
        configured = os.environ.get("DONINO_BOOTSTRAP_TOKEN_HASH", "")
        try:
            expiry = int(os.environ.get("DONINO_BOOTSTRAP_EXPIRES", "0"))
        except ValueError as exc:
            raise HTTPException(503, "Bootstrap configuration is invalid") from exc
        now = int(time.time())
        if len(configured) != 64 or expiry <= now:
            raise HTTPException(404, "Bootstrap unavailable or expired")
        address = "bootstrap:" + (request.client.host if request.client else "unknown")
        with database() as db:
            if db.execute("SELECT COUNT(*) FROM admins").fetchone()[0]:
                raise HTTPException(
                    409, "An administrator already exists; bootstrap is closed"
                )
            attempts = db.execute(
                "SELECT * FROM login_attempts WHERE address=?", (address,)
            ).fetchone()
            if attempts and attempts["until"] > now and attempts["attempts"] >= 10:
                raise HTTPException(429, "Too many setup attempts")
            if not hmac.compare_digest(digest(body.token), configured):
                count = (
                    attempts["attempts"] + 1
                    if attempts and attempts["until"] > now
                    else 1
                )
                db.execute(
                    "INSERT INTO login_attempts VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET attempts=excluded.attempts,until=excluded.until",
                    (address, count, now + 900),
                )
                return JSONResponse({"detail": "Invalid setup token"}, status_code=401)
            db.execute(
                "INSERT INTO admins(username,password,role) VALUES(?,?,'owner')",
                (body.username, hash_password(body.password)),
            )
            db.execute("DELETE FROM login_attempts WHERE address=?", (address,))
            audit(db, "bootstrap", "admin.first-owner", body.username)
        return {"username": body.username, "role": "owner", "login_required": True}
