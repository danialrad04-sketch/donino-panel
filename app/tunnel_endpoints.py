"""Point-in-time VPN acceptance and leased, additive subscription endpoints."""

import hashlib
import json
import time
import uuid

from fastapi import HTTPException
from pydantic import Field, field_validator, model_validator

from . import tunnel_bindings as bindings, tunnel_probe
from .core import profiles, is_reality, transport_of
from .db import audit, database
from .deps import one
from .tunnel_bridge import Input, State, enabled

FRESH_SECONDS = 600
LEASE_SECONDS = 86400


class VerifyInput(Input):
    device_id: str = Field(pattern=bindings.UUID)
    inbound_ids: list[str] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique(self):
        if len(set(self.inbound_ids)) != len(self.inbound_ids):
            raise ValueError("Duplicate inbound")
        for value in self.inbound_ids:
            uuid.UUID(value)
        return self


class PublishInput(Input):
    check_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    confirm_publish: bool

    @field_validator("confirm_publish", mode="before")
    @classmethod
    def explicit(cls, value):
        if value is not True:
            raise ValueError("Explicit publication confirmation required")
        return value


def worker_matches(row, state):
    profile = next((p for p in state["profiles"] if p["id"] == row["profile_id"]), None)
    job = next((j for j in state["jobs"] if j["id"] == row["job_id"]), None)
    return bool(
        state["available"]
        and not state["busy"]
        and row["phase"] == "succeeded"
        and profile
        and profile["management"] == "https-v1"
        and profile["host"] == row["peer_host"]
        and job
        and job["plan_id"] == row["plan_id"]
        and job["status"] == "succeeded"
        and not any(
            j["id"] != job["id"] and j["created"] >= job["created"]
            for j in state["jobs"]
        )
    )


def invalidate_all(db):
    from . import tunnel_monitor as monitor

    monitor.fence(db, error="monitor_worker_changed")
    if monitor.table_exists(db, "tunnel_monitor_runtime"):
        db.execute("DELETE FROM tunnel_monitor_runtime")
    # Every worker start replaces the whole managed set, including manual plans.
    db.execute("DELETE FROM tunnel_endpoints")
    db.execute(
        "UPDATE tunnel_checks SET phase='invalidated' WHERE phase IN ('running','succeeded')"
    )


def synchronize(db, state):
    from . import tunnel_monitor as monitor

    rows = list(
        db.execute(
            "SELECT DISTINCT b.* FROM tunnel_bindings b JOIN tunnel_checks c ON c.binding_id=b.id "
            "WHERE c.phase IN ('running','succeeded')"
        )
    )
    for row in rows:
        if not worker_matches(row, state):
            monitor.fence(db, row["id"], error="monitor_worker_changed")
            db.execute("DELETE FROM tunnel_endpoints WHERE binding_id=?", (row["id"],))
            db.execute(
                "UPDATE tunnel_checks SET phase='invalidated',error_code='worker_changed' "
                "WHERE binding_id=? AND phase IN ('running','succeeded')",
                (row["id"],),
            )
    # Failed probes have no positive receipt; their grants still need fencing.
    for row in db.execute(
        "SELECT b.* FROM tunnel_bindings b JOIN tunnel_monitors m ON m.binding_id=b.id WHERE m.enabled=1"
    ).fetchall():
        if not worker_matches(row, state):
            monitor.fence(db, row["id"], error="monitor_worker_changed")


def _guard(db, row, state):
    if not bindings.matches(db, row) or not worker_matches(row, state):
        raise HTTPException(409, "نصب جاری یا تنظیمات مبدأ با این نقشه مطابقت ندارد")


def _client(db, row, device_id):
    from .main import client_rows

    rows = client_rows(db, "WHERE d.id=?", (device_id,), node_id=row["node_id"])
    if not rows or not rows[0]["eligible"]:
        raise HTTPException(409, "دستگاه آزمون باید فعال و مجاز به استفاده از نود باشد")
    # Lease-quota probes need a budget-aware supervisor; do not bypass it.
    if rows[0]["quota_mode"] == "lease":
        raise HTTPException(409, "برای آزمون، دستگاهی با سهمیهٔ عادی انتخاب کنید")
    client = rows[0]
    revision = hashlib.sha256(
        bindings.canonical(
            {k: client[k] for k in ("id", "secret", "user_id", "period_no")}
        ).encode()
    ).hexdigest()
    return client, revision


def _profiles(db, row, selected, client):
    request = bindings.BoundPreview.model_validate_json(row["request"])
    choices = {s.inbound_id: s.listen_port for s in request.services}
    if not set(selected).issubset(choices):
        raise HTTPException(409, "اتصال انتخاب‌شده عضو این نقشه نیست")
    inbounds = []
    for inbound_id in selected:
        inbound = dict(one(db, "inbounds", inbound_id))
        if is_reality(
            inbound["protocol"],
            transport_of(inbound["protocol"], json.loads(inbound["settings"])),
        ):
            raise HTTPException(
                409, "آزمون تانل در این نسخه برای مسیرهای TLS عرضه شده است"
            )
        # Carrier dial address changes; original SNI, WS Host/path, gRPC and
        # credentials are compiled by the same serializer as subscriptions.
        inbound.update(
            host=request.iran,
            port=choices[inbound_id],
            node_name="Donino",
            node_enabled=True,
        )
        inbounds.append(inbound)
    return profiles([client], inbounds)[1]["proxies"]


def verify(binding_id, body, account, controller, *, monitor_claim=None):
    from . import tunnel_monitor as monitor

    if not tunnel_probe.available():
        raise HTTPException(
            503, "کلاینت و مقصد HTTPS آزمون روی میزبان پنل پیکربندی نشده است"
        )
    state = bindings.parsed(State, controller("GET", "/state"))
    bindings.list_bindings(state, binding_id)
    # Timestamp prefix orders same-second receipts on both DB backends; the
    # suffix keeps identity unique. IDs are public metadata, not credentials.
    check_id = f"{time.time_ns():016x}" + uuid.uuid4().hex[:16]
    started = int(time.time())
    with database() as db:
        row = one(db, "tunnel_bindings", binding_id)
        _guard(db, row, state)
        if monitor_claim:
            monitor.guard_claim(db, monitor_claim, row)
        # A crash leaves a bounded running receipt. A fresh explicit request
        # may supersede it after the controller/probe deadline; never auto retry.
        db.execute(
            "UPDATE tunnel_checks SET phase='failed',error_code='probe_interrupted' "
            "WHERE phase='running' AND started<?",
            (started - 360,),
        )
        if db.execute("SELECT 1 FROM tunnel_checks WHERE phase='running'").fetchone():
            raise HTTPException(409, "یک آزمون دیگر در حال اجراست؛ وضعیت را بررسی کنید")
        prune_checks(db)
        if db.execute("SELECT COUNT(*) FROM tunnel_checks").fetchone()[0] >= 5000:
            raise HTTPException(409, "ظرفیت تاریخچهٔ آزمون پر شده است")
        client, device_revision = _client(db, row, body.device_id)
        proxies = _profiles(db, row, body.inbound_ids, client)
        if not monitor_claim:
            monitor.fence(db, binding_id)
        # Retesting a selected path withdraws its old lease immediately. A new
        # failure cannot leave a previous positive proof available for publish.
        for prior in (
            []
            if monitor_claim
            else db.execute(
                "SELECT id,inbound_ids FROM tunnel_checks WHERE binding_id=? AND phase='succeeded'",
                (binding_id,),
            ).fetchall()
        ):
            if set(json.loads(prior["inbound_ids"])) & set(body.inbound_ids):
                db.execute(
                    "DELETE FROM tunnel_endpoints WHERE check_id=?", (prior["id"],)
                )
                db.execute(
                    "UPDATE tunnel_checks SET phase='invalidated' WHERE id=?",
                    (prior["id"],),
                )
        db.execute(
            "INSERT INTO tunnel_checks(id,binding_id,source_revision,job_id,device_id,device_revision,"
            "inbound_ids,phase,started) VALUES(?,?,?,?,?,?,?,'running',?)",
            (
                check_id,
                binding_id,
                row["source_revision"],
                row["job_id"],
                body.device_id,
                device_revision,
                json.dumps(body.inbound_ids),
                started,
            ),
        )
        audit(db, account["username"], "tunnel.verify.start", check_id)
    error = None
    try:
        tunnel_probe.run(proxies)
        # A second worker observation prevents blessing a replacement during I/O.
        after = bindings.parsed(State, controller("GET", "/state"))
        with database() as db:
            current = one(db, "tunnel_bindings", binding_id)
            _guard(db, current, after)
            if monitor_claim:
                monitor.guard_claim(db, monitor_claim, current)
            if _client(db, current, body.device_id)[1] != device_revision:
                raise HTTPException(409, "هویت دستگاه در حین آزمون تغییر کرد")
            if one(db, "tunnel_checks", check_id)["phase"] != "running":
                raise HTTPException(409, "آزمون با شروع نصب دیگری باطل شد")
    except tunnel_probe.ProbeError as failure:
        error = str(failure)
    except HTTPException:
        error = "probe_origin_changed"
    except Exception:
        # Do not leave a successful-looking receipt or expose exception details.
        error = "probe_internal_error"
    finished = int(time.time())
    with database() as db:
        if monitor_claim and not error:
            try:
                monitor.guard_claim(
                    db, monitor_claim, one(db, "tunnel_bindings", binding_id)
                )
            except (HTTPException, tunnel_probe.ProbeError):
                error = "monitor_cancelled"
        db.execute(
            "UPDATE tunnel_checks SET phase=?,finished=?,expires=?,error_code=? WHERE id=? AND phase='running'",
            (
                "failed" if error else "succeeded",
                finished,
                finished + FRESH_SECONDS,
                error,
                check_id,
            ),
        )
        audit(db, account["username"], "tunnel.verify.finish", check_id)
        return check_metadata(one(db, "tunnel_checks", check_id))


def prune_checks(db):
    """Bound continuous history, preserving running/fresh and published receipts."""
    # Keep the newest 1000 completed receipts globally, plus every live proof.
    rows = db.execute(
        "SELECT c.id FROM tunnel_checks c WHERE c.phase<>'running' AND COALESCE(c.expires,c.started+600)<? "
        "AND NOT EXISTS (SELECT 1 FROM tunnel_endpoints e WHERE e.check_id=c.id) "
        "AND NOT EXISTS (SELECT 1 FROM tunnel_monitors m WHERE m.last_check_id=c.id) "
        "ORDER BY c.started DESC,c.id DESC LIMIT 5000 OFFSET 1000",
        (int(time.time()),),
    ).fetchall()
    for row in rows:
        db.execute("DELETE FROM tunnel_checks WHERE id=?", (row["id"],))


def check_metadata(row):
    return {
        key: row[key]
        for key in (
            "id",
            "binding_id",
            "device_id",
            "phase",
            "started",
            "finished",
            "expires",
            "error_code",
        )
    } | {
        "inbound_ids": json.loads(row["inbound_ids"]),
        "engine": "mihomo",
        "engine_version": tunnel_probe.VERSION,
    }


def details(db, row):
    from . import tunnel_monitor as monitor

    checks = [
        check_metadata(c)
        for c in db.execute(
            "SELECT * FROM tunnel_checks WHERE binding_id=? ORDER BY started DESC,id DESC LIMIT 10",
            (row["id"],),
        )
    ]
    current = bindings.matches(db, row)
    published = (
        [
            dict(p)
            for p in db.execute(
                "SELECT inbound_id,check_id,created,expires FROM tunnel_endpoints WHERE binding_id=? AND expires>?",
                (row["id"], int(time.time())),
            )
        ]
        if current and enabled() and monitor.allowed(db, row)
        else []
    )
    return {
        "checks": checks,
        "published_inbounds": published,
        "application_verified": current
        and any(
            c["phase"] == "succeeded" and c["expires"] > time.time() for c in checks
        ),
        "endpoint_published": bool(published),
        "monitor": monitor.metadata(db, row["id"]),
    }


def publish(binding_id, body, account, controller, *, monitor_claim=None):
    from . import tunnel_monitor as monitor

    state = bindings.parsed(State, controller("GET", "/state"))
    bindings.list_bindings(state, binding_id)
    with database() as db:
        row = one(db, "tunnel_bindings", binding_id)
        _guard(db, row, state)
        if monitor_claim:
            monitor.guard_claim(db, monitor_claim, row)
        check = one(db, "tunnel_checks", body.check_id)
        if (
            check["binding_id"] != binding_id
            or check["phase"] != "succeeded"
            or check["source_revision"] != row["source_revision"]
            or check["job_id"] != row["job_id"]
            or check["expires"] <= time.time()
            or _client(db, row, check["device_id"])[1] != check["device_revision"]
        ):
            raise HTTPException(409, "تأیید انتقال معتبر و تازه برای انتشار لازم است")
        ids = json.loads(check["inbound_ids"])
        if monitor_claim and (
            set(ids) != set(json.loads(monitor_claim["inbound_ids"]))
            or check["device_id"] != monitor_claim["device_id"]
        ):
            raise HTTPException(409, "آزمون خارج از محدودهٔ رضایت پایش است")
        if not monitor_claim:
            previous = monitor._row(db, binding_id)
            if previous and previous["enabled"]:
                db.execute(
                    "DELETE FROM tunnel_endpoints WHERE binding_id=?", (binding_id,)
                )
            monitor.fence(db, binding_id, withdraw_endpoints=False)
        now = int(time.time())
        for inbound_id in ids:
            existing = db.execute(
                "SELECT * FROM tunnel_endpoints WHERE inbound_id=?", (inbound_id,)
            ).fetchone()
            if (
                existing
                and existing["binding_id"] != binding_id
                and existing["expires"] > now
            ):
                raise HTTPException(409, "ابتدا انتشار نقشهٔ قبلی این ورودی را لغو کنید")
            db.execute(
                "INSERT INTO tunnel_endpoints(inbound_id,binding_id,check_id,created,expires) VALUES(?,?,?,?,?) "
                "ON CONFLICT(inbound_id) DO UPDATE SET binding_id=excluded.binding_id,check_id=excluded.check_id,created=excluded.created,expires=excluded.expires",
                (inbound_id, binding_id, check["id"], now, now + LEASE_SECONDS),
            )
        audit(db, account["username"], "tunnel.publish", binding_id)
        if monitor_claim:
            monitor.succeeded(db, monitor_claim, check["id"])
        return details(db, row)


def unpublish(binding_id, account):
    from . import tunnel_monitor as monitor

    with database() as db:
        row = one(db, "tunnel_bindings", binding_id)
        monitor.fence(db, binding_id)
        db.execute("DELETE FROM tunnel_endpoints WHERE binding_id=?", (binding_id,))
        audit(db, account["username"], "tunnel.unpublish", binding_id)
        return details(db, row)


def subscription_rows(db, inbounds):
    from . import tunnel_monitor as monitor

    if not enabled():
        return list(inbounds)
    candidates = list(
        db.execute(
            "SELECT e.inbound_id,e.binding_id FROM tunnel_endpoints e JOIN tunnel_checks c ON c.id=e.check_id "
            "WHERE e.expires>? AND c.phase='succeeded'",
            (int(time.time()),),
        )
    )
    origins = {row["id"]: row for row in inbounds}
    result, cache = list(inbounds), {}
    for item in candidates:
        if item["inbound_id"] not in origins:
            continue
        bid = item["binding_id"]
        if bid not in cache:
            row = one(db, "tunnel_bindings", bid)
            cache[bid] = (
                bindings.BoundPreview.model_validate_json(row["request"])
                if bindings.matches(db, row)
                and row["phase"] == "succeeded"
                and monitor.allowed(db, row)
                else None
            )
        spec = cache[bid]
        if not spec:
            continue
        service = next(s for s in spec.services if s.inbound_id == item["inbound_id"])
        origin = dict(origins[item["inbound_id"]])
        origin.update(
            host=spec.iran, port=service.listen_port, name=origin["name"] + " · تانل"
        )
        result.append(origin)
    return result
