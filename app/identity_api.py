"""Routes for the first independently deliverable foundation increment."""

import base64
import json
import secrets
import time
import uuid
from urllib.parse import quote, urlencode

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from .db import audit, database, digest, verify_password
from .identity import PROTOCOLS, ensure_identity
from .security import cipher, new_recovery_codes, verify_factor, verify_totp


class DeviceInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    expires: int | None = Field(default=None, gt=0, le=32_503_680_000)


class Assignment(BaseModel):
    mode: str = Field(pattern=r"^(all|selected)$")
    user_ids: list[str] = Field(default_factory=list, max_length=10000)


class FactorInput(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(default="", max_length=6)
    recovery_code: str = Field(default="", max_length=32)


class CodeInput(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class TokenInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scopes: list[str] = Field(min_length=1, max_length=10)
    expires: int = Field(gt=0)


def mount_identity_routes(app, admin, writer, owner, one):
    @app.get("/api/users/{uid}/devices")
    def list_devices(uid: str, account=Depends(writer)):
        with database() as db:
            ensure_identity(db, one(db, "users", uid))
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM devices WHERE user_id=? ORDER BY created,id", (uid,)
                )
            ]

    @app.post("/api/users/{uid}/devices", status_code=201)
    def create_device(uid: str, body: DeviceInput, account=Depends(writer)):
        did, now = str(uuid.uuid4()), int(time.time())
        with database() as db:
            ensure_identity(db, one(db, "users", uid))
            db.execute(
                "INSERT INTO devices(id,user_id,name,enabled,expires,created) VALUES(?,?,?,?,?,?)",
                (did, uid, body.name, body.enabled, body.expires, now),
            )
            for protocol in PROTOCOLS:
                db.execute(
                    "INSERT INTO credentials(id,device_id,protocol,secret) VALUES(?,?,?,?)",
                    (str(uuid.uuid4()), did, protocol, str(uuid.uuid4())),
                )
            audit(db, account["username"], "device.create", did)
        return {"id": did, "user_id": uid, **body.model_dump(), "created": now}

    @app.put("/api/users/{uid}/devices/{did}")
    def update_device(uid: str, did: str, body: DeviceInput, account=Depends(writer)):
        with database() as db:
            device = one(db, "devices", did)
            if device["user_id"] != uid:
                raise HTTPException(404, "Device not found")
            db.execute(
                "UPDATE devices SET name=?,enabled=?,expires=? WHERE id=?",
                (body.name, body.enabled, body.expires, did),
            )
            audit(db, account["username"], "device.update", did)
        return {"id": did, **body.model_dump()}

    @app.post("/api/users/{uid}/devices/{did}/rotate")
    def rotate_device(uid: str, did: str, account=Depends(writer)):
        with database() as db:
            device = one(db, "devices", did)
            if device["user_id"] != uid:
                raise HTTPException(404, "Device not found")
            for credential in db.execute(
                "SELECT id FROM credentials WHERE device_id=?", (did,)
            ):
                db.execute(
                    "UPDATE credentials SET secret=?,generation=generation+1 WHERE id=?",
                    (str(uuid.uuid4()), credential["id"]),
                )
            audit(db, account["username"], "device.rotate", did)
        return {"ok": True}

    @app.get("/api/users/{uid}/periods")
    def periods(uid: str, account=Depends(writer)):
        with database() as db:
            ensure_identity(db, one(db, "users", uid))
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM user_periods WHERE user_id=? ORDER BY started DESC,id",
                    (uid,),
                )
            ]

    @app.get("/api/nodes/{nid}/assignments")
    def get_assignments(nid: str, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", nid)
            policy = db.execute(
                "SELECT mode FROM node_policy WHERE node_id=?", (nid,)
            ).fetchone()
            return {
                "mode": policy["mode"] if policy else "all",
                "user_ids": [
                    r["user_id"]
                    for r in db.execute(
                        "SELECT user_id FROM user_nodes WHERE node_id=? ORDER BY user_id",
                        (nid,),
                    )
                ],
            }

    @app.put("/api/nodes/{nid}/assignments")
    def assignments(nid: str, body: Assignment, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", nid)
            db.lock("assignments:" + nid)
            for uid in set(body.user_ids):
                one(db, "users", uid)
            db.execute(
                "INSERT INTO node_policy(node_id,mode) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET mode=excluded.mode",
                (nid, body.mode),
            )
            db.execute("DELETE FROM user_nodes WHERE node_id=?", (nid,))
            for uid in set(body.user_ids):
                db.execute(
                    "INSERT INTO user_nodes(node_id,user_id) VALUES(?,?)", (nid, uid)
                )
            audit(db, account["username"], "node.assignments", nid)
        return {"mode": body.mode, "user_ids": sorted(set(body.user_ids))}

    @app.get("/api/security/mfa")
    def mfa_status(account=Depends(admin)):
        with database() as db:
            row = db.execute(
                "SELECT enabled FROM admin_mfa WHERE username=?", (account["username"],)
            ).fetchone()
        return {"enabled": bool(row and row["enabled"])}

    def reauthenticate(db, account, body):
        row = db.execute(
            "SELECT password FROM admins WHERE username=?", (account["username"],)
        ).fetchone()
        if (
            not row
            or not verify_password(body.password, row["password"])
            or not verify_factor(db, account["username"], body.code, body.recovery_code)
        ):
            raise HTTPException(401, "Invalid authentication")

    @app.post("/api/security/mfa/setup")
    def mfa_setup(body: FactorInput, account=Depends(admin)):
        if account.get("api_token"):
            raise HTTPException(403, "Use an interactive session")
        with database() as db:
            reauthenticate(db, account, body)
            current = db.execute(
                "SELECT enabled FROM admin_mfa WHERE username=?", (account["username"],)
            ).fetchone()
            if current and current["enabled"]:
                raise HTTPException(409, "Disable existing MFA before reenrollment")
            seed = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            encrypted = cipher().encrypt(seed.encode()).decode()
            db.execute(
                "INSERT INTO admin_mfa(username,secret) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET secret=excluded.secret,last_step=-1",
                (account["username"], encrypted),
            )
            audit(db, account["username"], "mfa.setup")
        return {
            "secret": seed,
            "otpauth_uri": "otpauth://totp/Donino:"
            + quote(account["username"], safe="")
            + "?"
            + urlencode(
                {
                    "secret": seed,
                    "issuer": "Donino",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "period": 30,
                }
            ),
        }

    @app.post("/api/security/mfa/enable")
    def mfa_enable(body: CodeInput, account=Depends(admin)):
        if account.get("api_token"):
            raise HTTPException(403, "Use an interactive session")
        with database() as db:
            db.lock("mfa:" + account["username"])
            row = db.execute(
                "SELECT * FROM admin_mfa WHERE username=?", (account["username"],)
            ).fetchone()
            if not row or row["enabled"] or not verify_totp(db, row, body.code):
                raise HTTPException(400, "Invalid MFA confirmation")
            db.execute(
                "UPDATE admin_mfa SET enabled=1 WHERE username=?",
                (account["username"],),
            )
            codes = new_recovery_codes(db, account["username"])
            db.execute("DELETE FROM sessions WHERE username=?", (account["username"],))
            db.execute(
                "DELETE FROM api_tokens WHERE username=?", (account["username"],)
            )
            audit(db, account["username"], "mfa.enable")
        return {
            "enabled": True,
            "recovery_codes": codes,
            "reauthentication_required": True,
        }

    @app.post("/api/security/mfa/disable")
    def mfa_disable(body: FactorInput, account=Depends(admin)):
        if account.get("api_token"):
            raise HTTPException(403, "Use an interactive session")
        with database() as db:
            reauthenticate(db, account, body)
            db.execute("DELETE FROM admin_mfa WHERE username=?", (account["username"],))
            db.execute(
                "DELETE FROM recovery_codes WHERE username=?", (account["username"],)
            )
            db.execute("DELETE FROM sessions WHERE username=?", (account["username"],))
            db.execute(
                "DELETE FROM api_tokens WHERE username=?", (account["username"],)
            )
            audit(db, account["username"], "mfa.disable")
        return {"enabled": False, "reauthentication_required": True}

    @app.post("/api/security/tokens", status_code=201)
    def token_create(body: TokenInput, account=Depends(admin)):
        if account.get("api_token"):
            raise HTTPException(403, "Use an interactive session")
        scopes = set(body.scopes)
        permitted = {
            "users:read",
            "users:write",
            "nodes:read",
            "nodes:write",
            "inbounds:read",
            "inbounds:write",
            "audit:read",
        }
        role_scopes = (
            permitted
            if account["role"] == "owner"
            else {"users:read", "nodes:read", "inbounds:read"}
            | ({"users:write"} if account["role"] == "operator" else set())
        )
        now = int(time.time())
        if not scopes <= role_scopes or not now < body.expires <= now + 366 * 86400:
            raise HTTPException(422, "Invalid scopes or expiry (maximum 366 days)")
        token, tid = "donino_" + secrets.token_urlsafe(40), str(uuid.uuid4())
        with database() as db:
            db.execute(
                "INSERT INTO api_tokens(id,digest,username,name,scopes,expires,created) VALUES(?,?,?,?,?,?,?)",
                (
                    tid,
                    digest(token),
                    account["username"],
                    body.name,
                    json.dumps(sorted(scopes)),
                    body.expires,
                    now,
                ),
            )
            audit(db, account["username"], "api-token.create", tid)
        return {
            "id": tid,
            "token": token,
            "expires": body.expires,
            "scopes": sorted(scopes),
        }

    @app.get("/api/security/tokens")
    def tokens(account=Depends(admin)):
        with database() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT id,name,scopes,expires,created,last_used FROM api_tokens WHERE username=? ORDER BY created DESC",
                    (account["username"],),
                )
            ]

    @app.delete("/api/security/tokens/{tid}")
    def token_delete(tid: str, account=Depends(admin)):
        with database() as db:
            db.execute(
                "DELETE FROM api_tokens WHERE id=? AND username=?",
                (tid, account["username"]),
            )
            audit(db, account["username"], "api-token.delete", tid)
        return {"ok": True}
