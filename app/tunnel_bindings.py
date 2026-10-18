"""Durable, revision-guarded plans compiled from existing VPN inbounds.

Worker success means carrier installation/probes, not application acceptance.
Bindings never change subscription endpoints or grant access to imported users.
"""

import base64
import hashlib
import json
import math
import time
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import Field, field_validator, model_validator

from .db import audit, database
from .deps import one
from .tunnel_bridge import Input, Job, Preview, PreviewInput, State, validate_host

UUID = r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def service_id(inbound_id):
    # Full UUID identity in 30 characters; the pinned worker permits <=32.
    return "vpn-" + base64.b32encode(
        uuid.UUID(inbound_id).bytes
    ).decode().lower().rstrip("=")


class BoundService(Input):
    inbound_id: str = Field(pattern=UUID)
    listen_port: int = Field(ge=1, le=65535)


class BoundPreview(Input):
    node_id: str = Field(pattern=UUID)
    profile_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    iran: str = Field(min_length=1, max_length=253)
    services: list[BoundService] = Field(min_length=1, max_length=40)
    transports: list[Literal["frp-wss", "frp-quic"]] = Field(min_length=1, max_length=2)
    base_port: int = Field(default=30000, ge=1024, le=65000)
    carrier_base: int = Field(default=24443, ge=1024, le=65000)
    health_port: int = Field(default=19090, ge=1024, le=65535)

    _host = field_validator("iran")(validate_host)

    @model_validator(mode="after")
    def unique(self):
        for field in ("inbound_id", "listen_port"):
            if len({getattr(row, field) for row in self.services}) != len(
                self.services
            ):
                raise ValueError("Duplicate inbound or public port")
        if len(set(self.transports)) != len(self.transports):
            raise ValueError("Duplicate carrier")
        return self


class ConfirmBinding(Input):
    confirm_replace: bool

    @model_validator(mode="after")
    def explicit(self):
        if self.confirm_replace is not True:
            raise ValueError("Explicit replacement confirmation required")
        return self


def source(db, body):
    node = one(db, "nodes", body.node_id)
    if not node["enabled"]:
        raise HTTPException(409, "نود مقصد غیرفعال است")
    rows, services = [], []
    for item in sorted(body.services, key=lambda row: row.inbound_id):
        inbound = one(db, "inbounds", item.inbound_id)
        if inbound["node_id"] != node["id"] or not inbound["enabled"]:
            raise HTTPException(409, "اتصال‌ها باید فعال و متعلق به نود انتخاب‌شده باشند")
        rows.append(
            {
                "id": inbound["id"],
                "protocol": inbound["protocol"],
                "port": inbound["port"],
                "settings": json.loads(inbound["settings"]),
            }
        )
        services.append(
            {
                "id": service_id(inbound["id"]),
                "listen_port": item.listen_port,
                "target_port": inbound["port"],
            }
        )
    revision = hashlib.sha256(
        canonical(
            {
                "node_id": node["id"],
                "host": node["host"],
                "inbounds": rows,
            }
        ).encode()
    ).hexdigest()
    fields = body.model_dump(exclude={"node_id", "services"})
    spec = PreviewInput.model_validate({**fields, "services": services}).worker_spec()
    return revision, spec


def matches(db, row):
    try:
        body = BoundPreview.model_validate_json(row["request"])
        return source(db, body)[0] == row["source_revision"]
    except (HTTPException, ValueError):
        return False


def metadata(db, row):
    from .tunnel_endpoints import details

    current = matches(db, row)
    return {
        "id": row["id"],
        "node_id": row["node_id"],
        "profile_id": row["profile_id"],
        "peer_host": row["peer_host"],
        "phase": row["phase"],
        "plan_id": row["plan_id"],
        "job_id": row["job_id"],
        "source_revision": row["source_revision"],
        "services": json.loads(row["request"])["services"],
        "source_matches": current,
        "summary": json.loads(row["summary"]) if row["summary"] else None,
        "expires_at": row["expires"],
        "error_code": row["error_code"],
        "created": row["created"],
        "updated": row["updated"],
        "can_start": current
        and row["phase"] == "previewed"
        and row["expires"] > time.time(),
        **details(db, row),
    }


def list_bindings(worker=None, binding_id=None):
    from .tunnel_endpoints import synchronize

    with database() as db:
        rows = (
            [one(db, "tunnel_bindings", binding_id)]
            if binding_id
            else list(
                db.execute(
                    "SELECT * FROM tunnel_bindings ORDER BY created DESC,id DESC LIMIT 100"
                )
            )
        )
        if worker:
            jobs = {job["plan_id"]: job for job in worker["jobs"]}
            for row in rows:
                job = jobs.get(row["plan_id"])
                if not job or row["phase"] not in {
                    "starting",
                    "start_unknown",
                    "running",
                    "succeeded",
                    "failed",
                    "interrupted",
                    "rollback_failed",
                }:
                    continue
                if row["job_id"] and row["job_id"] != job["id"]:
                    continue
                if (
                    row["phase"] == job["status"]
                    and row["job_id"] == job["id"]
                    and not row["error_code"]
                ):
                    continue
                db.execute(
                    "UPDATE tunnel_bindings SET phase=?,job_id=?,error_code=NULL,updated=? WHERE id=?",
                    (job["status"], job["id"], int(time.time()), row["id"]),
                )
            synchronize(db, worker)
        return [metadata(db, one(db, "tunnel_bindings", row["id"])) for row in rows]


def _update(binding_id, phase, error=None, expected=None):
    with database() as db:
        clause = " AND phase=?" if expected else ""
        args = (phase, error, int(time.time()), binding_id)
        db.execute(
            "UPDATE tunnel_bindings SET phase=?,error_code=?,updated=? WHERE id=?"
            + clause,
            args + ((expected,) if expected else ()),
        )


def parsed(model, value):
    try:
        return model.model_validate(value).model_dump()
    except ValueError:
        raise HTTPException(
            502, "پاسخ کنترل‌کننده با قرارداد تانل سازگار نیست"
        ) from None


def peer(state, profile_id):
    profile = next(
        (
            p
            for p in state["profiles"]
            if p["id"] == profile_id and p["management"] == "https-v1"
        ),
        None,
    )
    if not profile:
        raise HTTPException(409, "اتصال HTTPS جفت‌شدهٔ خارج در دسترس نیست")
    return profile


def create(body, account, controller):
    # No database transaction/lock is held during a worker/network request.
    state = parsed(State, controller("GET", "/state"))
    profile = peer(state, body.profile_id)
    binding_id, now = uuid.uuid4().hex, int(time.time())
    with database() as db:
        if db.execute("SELECT COUNT(*) FROM tunnel_bindings").fetchone()[0] >= 1000:
            raise HTTPException(409, "ظرفیت تاریخچهٔ نقشهٔ تانل پر شده است")
        revision, spec = source(db, body)
        db.execute(
            "INSERT INTO tunnel_bindings(id,node_id,profile_id,peer_host,source_revision,request,phase,created,updated) VALUES(?,?,?,?,?,?,'preparing',?,?)",
            (
                binding_id,
                body.node_id,
                body.profile_id,
                profile["host"],
                revision,
                canonical(body.model_dump()),
                now,
                now,
            ),
        )
        audit(db, account["username"], "tunnel.binding.prepare", binding_id)
    try:
        preview = parsed(Preview, controller("POST", "/preview", spec))
        summary = preview["summary"]
        if (
            summary["services"] != spec["services"]
            or summary["iran"] != body.iran
            or summary["foreign"] != profile["host"]
            or summary["transports"] != body.transports
            or not math.isfinite(preview["expires_at"])
            or not time.time() < preview["expires_at"] <= time.time() + 3660
        ):
            raise HTTPException(502, "نقشهٔ برگشتی با ورودی‌های انتخاب‌شده مطابقت ندارد")
    except HTTPException:
        _update(binding_id, "preview_unknown", "preview_response_unavailable")
        raise
    with database() as db:
        row = one(db, "tunnel_bindings", binding_id)
        changed = not matches(db, row)
        db.execute(
            "UPDATE tunnel_bindings SET phase=?,plan_id=?,summary=?,expires=?,error_code=?,updated=? WHERE id=?",
            (
                "stale" if changed else "previewed",
                preview["id"],
                canonical(summary),
                int(preview["expires_at"]),
                "source_changed" if changed else None,
                int(time.time()),
                binding_id,
            ),
        )
        result = metadata(db, one(db, "tunnel_bindings", binding_id))
    if changed:
        raise HTTPException(
            409, "تنظیمات نود حین ساخت نقشه تغییر کرد؛ نقشهٔ تازه بسازید"
        )
    return result


def start(binding_id, account, controller):
    # Reconcile a lost start response by the worker's durable plan/job identity.
    state = parsed(State, controller("GET", "/state"))
    row = list_bindings(state, binding_id)[0]
    if row["phase"] in {"running", "succeeded"}:
        return row
    profile = peer(state, row["profile_id"])
    error = None
    with database() as db:
        current = one(db, "tunnel_bindings", binding_id)
        if current["phase"] != "previewed":
            raise HTTPException(
                409, "این نقشه قابل شروع نیست؛ ابتدا وضعیت عملیات را بررسی کنید"
            )
        if not matches(db, current) or profile["host"] != current["peer_host"]:
            error = "source_changed"
        elif current["expires"] <= time.time():
            error = "expired"
        db.execute(
            "UPDATE tunnel_bindings SET phase=?,error_code=?,updated=? WHERE id=?",
            ("stale" if error else "starting", error, int(time.time()), binding_id),
        )
        plan_id = current["plan_id"]
        if not error:
            from .tunnel_endpoints import invalidate_all

            invalidate_all(db)
            audit(db, account["username"], "tunnel.binding.start", binding_id)
    if error:
        raise HTTPException(
            409, "تنظیمات یا اعتبار نقشه تغییر کرده است؛ نقشهٔ تازه بسازید"
        )
    try:
        job = parsed(
            Job,
            controller("POST", "/start", {"plan_id": plan_id, "confirm_replace": True}),
        )
        if job["plan_id"] != plan_id:
            raise HTTPException(502, "شناسهٔ عملیات با نقشه مطابقت ندارد")
    except HTTPException:
        _update(
            binding_id,
            "start_unknown",
            "start_response_unavailable",
            expected="starting",
        )
        raise
    with database() as db:
        current = one(db, "tunnel_bindings", binding_id)
        if current["phase"] in {
            "succeeded",
            "failed",
            "interrupted",
            "rollback_failed",
        }:
            return metadata(db, current)
        db.execute(
            "UPDATE tunnel_bindings SET phase=?,job_id=?,error_code=NULL,updated=? WHERE id=?",
            (job["status"], job["id"], int(time.time()), binding_id),
        )
        return metadata(db, one(db, "tunnel_bindings", binding_id))
