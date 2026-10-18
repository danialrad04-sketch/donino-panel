"""Typed owner-managed Smart DNS exit nodes. Credentials never leave the API."""

import asyncio
import json
import re
import time
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import Field, field_validator
from starlette.responses import JSONResponse

from .db import audit, database
from .deps import admin, one, owner
from .secrets import seal
from .smart_wire import close, connect_exit
from .tunnel_bridge import Input, validate_host
from . import smart_dns


class ExitInput(Input):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=9445, ge=1, le=65535)
    sni: str = Field(min_length=1, max_length=253)
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128)
    mode: Literal["active", "drain", "disabled"] = "disabled"

    _host = field_validator("host", "sni")(validate_host)

    @field_validator("username", "password")
    @classmethod
    def ascii_credentials(cls, value):
        if value and (len(value) < 12 or not re.fullmatch(r"[!-~]+", value)):
            raise ValueError("Use 12+ printable ASCII credential characters")
        return value


def public(row):
    return {
        key: row[key]
        for key in (
            "id",
            "name",
            "host",
            "port",
            "sni",
            "mode",
            "healthy",
            "checked",
            "latency",
            "error_code",
            "revision",
            "created",
            "updated",
        )
    }


class PrivateRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(
                    {"detail": "مشخصات نود خروجی معتبر نیست"}, status_code=422
                )

        return safe


def mount_smart_api(app):
    router = APIRouter(route_class=PrivateRoute)

    @router.get("/api/dns/smart/status")
    def status(account=Depends(admin)):
        try:
            addresses = smart_dns.front_addresses()
        except ValueError:
            addresses = []
        with database() as db:
            ready = smart_dns.gateway_ready(db) if addresses else False
        return {
            "enabled": smart_dns.enabled(),
            "gateway_ready": ready,
            "front_addresses": addresses,
            "transport": "https-sni",
            "game_acceptance": "untested",
        }

    @router.get("/api/dns/smart/exits")
    def exits(account=Depends(admin)):
        with database() as db:
            return [
                public(row)
                for row in db.execute(
                    "SELECT * FROM smart_exits ORDER BY name,id LIMIT 100"
                )
            ]

    def save(body, account, exit_id=None):
        now = int(time.time())
        with database() as db:
            old = dict(one(db, "smart_exits", exit_id)) if exit_id else None
            if (
                not old
                and db.execute("SELECT COUNT(*) FROM smart_exits").fetchone()[0] >= 100
            ):
                raise HTTPException(409, "ظرفیت نودهای خروجی پر است")
            if not old and (not body.username or not body.password):
                raise HTTPException(422, "نام کاربری و رمز خصوصی خروجی لازم‌اند")
            username = body.username or (old["username"] if old else "")
            changed = (
                not old
                or any(
                    getattr(body, key) != old[key] for key in ("host", "port", "sni")
                )
                or bool(body.password)
                or username != old["username"]
            )
            if changed and body.mode != "disabled":
                raise HTTPException(
                    409,
                    "پس از تغییر اتصال، ابتدا نود را غیرفعال ذخیره و سپس TLS و احراز هویت را آزمون کنید",
                )
            if body.mode == "active" and (
                not old
                or not old["healthy"]
                or not old["checked"]
                or old["checked"] < now - 300
            ):
                raise HTTPException(
                    409, "برای فعال‌سازی، آزمون TLS و احراز هویت تازه لازم است"
                )
            revision = str(uuid.uuid4()) if changed else old["revision"]
            password = seal(body.password) if body.password else old["password"]
            exit_id = exit_id or str(uuid.uuid4())
            db.execute(
                "INSERT INTO smart_exits(id,name,host,port,sni,username,password,mode,checked,healthy,latency,error_code,revision,created,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "name=excluded.name,host=excluded.host,port=excluded.port,sni=excluded.sni,username=excluded.username,password=excluded.password,"
                "mode=excluded.mode,checked=excluded.checked,healthy=excluded.healthy,latency=excluded.latency,error_code=excluded.error_code,revision=excluded.revision,updated=excluded.updated",
                (
                    exit_id,
                    body.name,
                    body.host,
                    body.port,
                    body.sni,
                    username,
                    password,
                    body.mode,
                    None if changed else old["checked"],
                    None if changed else old["healthy"],
                    None if changed else old["latency"],
                    None if changed else old["error_code"],
                    revision,
                    old["created"] if old else now,
                    now,
                ),
            )
            audit(db, account["username"], "smart.exit.save", exit_id)
            return public(one(db, "smart_exits", exit_id))

    @router.post("/api/dns/smart/exits", status_code=201)
    def create(body: ExitInput, account=Depends(owner)):
        return save(body, account)

    @router.put("/api/dns/smart/exits/{exit_id}")
    def update(exit_id: str, body: ExitInput, account=Depends(owner)):
        return save(body, account, exit_id)

    @router.post("/api/dns/smart/exits/{exit_id}/probe")
    def probe(exit_id: str, account=Depends(owner)):
        with database() as db:
            row = dict(one(db, "smart_exits", exit_id))

        async def check():
            import os

            writer = None
            start = time.monotonic()
            try:
                config = smart_dns.private_exit(row)
                _, writer = await connect_exit(
                    config, ca=os.environ.get("DONINO_SMART_DNS_CA") or None
                )
                return True, int((time.monotonic() - start) * 1000)
            except Exception:
                return False, 0
            finally:
                await close(writer)

        ok, latency = asyncio.run(check())
        smart_dns.health(exit_id, row["revision"], ok, latency)
        with database() as db:
            audit(db, account["username"], "smart.exit.probe", exit_id)
            result = public(one(db, "smart_exits", exit_id))
        return {
            **result,
            "ok": ok and result["revision"] == row["revision"],
            "application_verified": False,
        }

    @router.delete("/api/dns/smart/exits/{exit_id}")
    def delete(exit_id: str, account=Depends(owner)):
        with database() as db:
            one(db, "smart_exits", exit_id)
            for row in db.execute("SELECT rules FROM dns_policies"):
                if any(
                    exit_id in rule.get("exit_ids", [])
                    for rule in json.loads(row["rules"])
                ):
                    raise HTTPException(409, "ابتدا این نود را از قواعد سیاست حذف کنید")
            db.execute("DELETE FROM smart_exits WHERE id=?", (exit_id,))
            audit(db, account["username"], "smart.exit.delete", exit_id)
        return {"ok": True}

    @router.get("/api/dns/smart/sessions")
    def sessions(account=Depends(admin)):
        with database() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT s.*,u.name AS user_name,e.name AS exit_name FROM smart_sessions s "
                    "JOIN dns_accounts a ON a.id=s.account_id JOIN users u ON u.id=a.user_id "
                    "LEFT JOIN smart_exits e ON e.id=s.exit_id ORDER BY created DESC,id DESC LIMIT 100"
                )
            ]

    app.include_router(router)
