"""Consented, fenced renewal of one installed tunnel; never installs or reroutes."""

import json
import os
import time
import uuid

from fastapi import HTTPException
from pydantic import Field, field_validator

from . import tunnel_bindings as bindings, tunnel_endpoints as endpoints, tunnel_probe
from .db import audit, database, table_exists
from .deps import one
from .tunnel_bridge import Input, enabled as bridge_enabled

HEARTBEAT_SECONDS = 30
CLAIM_SECONDS = 360
MAX_MONITORS = 4


class MonitorInput(Input):
    check_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    confirm_auto_renew: bool
    interval_seconds: int = Field(default=300, ge=300, le=3600)

    @field_validator("confirm_auto_renew", mode="before")
    @classmethod
    def explicit(cls, value):
        if value is not True:
            raise ValueError("Explicit automatic renewal consent required")
        return value


def configured():
    return os.environ.get("DONINO_TUNNEL_MONITOR") == "1" and bridge_enabled()


def ready(db, instance_id=None):
    if not configured() or not tunnel_probe.available():
        return False
    row = db.execute("SELECT * FROM tunnel_monitor_runtime WHERE id=1").fetchone()
    return bool(
        row
        and row["lease_until"] > time.time()
        and (instance_id is None or row["instance_id"] == instance_id)
    )


def heartbeat(instance_id):
    """One live scheduler per database, including overlapping service restarts."""
    now = int(time.time())
    with database() as db:
        row = db.execute("SELECT * FROM tunnel_monitor_runtime WHERE id=1").fetchone()
        if row and row["instance_id"] != instance_id and row["lease_until"] > now:
            return False
        db.execute(
            "INSERT INTO tunnel_monitor_runtime(id,instance_id,lease_until) VALUES(1,?,?) "
            "ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,lease_until=excluded.lease_until",
            (instance_id, now + HEARTBEAT_SECONDS),
        )
        return True


def release(instance_id):
    with database() as db:
        db.execute(
            "DELETE FROM tunnel_monitor_runtime WHERE instance_id=?", (instance_id,)
        )


def _row(db, binding_id):
    return db.execute(
        "SELECT * FROM tunnel_monitors WHERE binding_id=?", (binding_id,)
    ).fetchone()


def withdraw(db, binding_id):
    db.execute("DELETE FROM tunnel_endpoints WHERE binding_id=?", (binding_id,))
    db.execute(
        "UPDATE tunnel_checks SET phase='invalidated' WHERE binding_id=? AND phase='succeeded'",
        (binding_id,),
    )


def fence(db, binding_id=None, *, error="monitor_disabled", withdraw_endpoints=True):
    # Older backup snapshots are invalidated before migration creates this table.
    if not table_exists(db, "tunnel_monitors"):
        return
    rows = list(
        db.execute(
            "SELECT binding_id FROM tunnel_monitors"
            + (" WHERE binding_id=?" if binding_id else ""),
            (binding_id,) if binding_id else (),
        )
    )
    for row in rows:
        bid = row[0]  # restore also uses a raw SQLite connection without row_factory
        db.execute(
            "UPDATE tunnel_monitors SET enabled=0,revision=?,phase='disabled',run_id=NULL,"
            "instance_id=NULL,claim_until=NULL,error_code=?,updated=? WHERE binding_id=?",
            (uuid.uuid4().hex, error, int(time.time()), bid),
        )
        if withdraw_endpoints:
            withdraw(db, bid)


def _scope(db, monitor, binding):
    owner = db.execute(
        "SELECT role FROM admins WHERE username=?", (monitor["actor"],)
    ).fetchone()
    if (
        not owner
        or owner["role"] != "owner"
        or binding["source_revision"] != monitor["source_revision"]
        or binding["job_id"] != monitor["job_id"]
        or binding["phase"] != "succeeded"
        or not bindings.matches(db, binding)
        or endpoints._client(db, binding, monitor["device_id"])[1]
        != monitor["device_revision"]
        or tunnel_probe.configuration_revision() != monitor["probe_revision"]
    ):
        raise HTTPException(
            409, "محدودهٔ رضایت پایش تغییر کرده است؛ پذیرش و تأیید تازه لازم است"
        )


def allowed(db, binding):
    """A stale/dead scheduler must not leave a 24-hour automatic lease visible."""
    monitor = _row(db, binding["id"])
    if not monitor or not monitor["enabled"]:
        return True
    if (
        not ready(db)
        or monitor["phase"] not in ("healthy", "checking")
        or not monitor["last_success"]
        or monitor["last_success"] + monitor["interval_seconds"] + CLAIM_SECONDS
        <= time.time()
    ):
        return False
    try:
        _scope(db, monitor, binding)
        return True
    except (HTTPException, tunnel_probe.ProbeError, ValueError):
        return False


def metadata(db, binding_id):
    row = _row(db, binding_id)
    result = {"service_ready": ready(db), "enabled": False, "phase": "disabled"}
    if row:
        result.update(
            {
                key: row[key]
                for key in (
                    "enabled",
                    "phase",
                    "interval_seconds",
                    "next_run",
                    "last_started",
                    "last_finished",
                    "last_success",
                    "last_check_id",
                    "error_code",
                    "failures",
                )
            }
        )
        result["enabled"] = bool(row["enabled"])
        result["inbound_ids"] = json.loads(row["inbound_ids"])
        if (
            row["enabled"]
            and row["phase"] in ("healthy", "checking")
            and row["last_success"] + row["interval_seconds"] + CLAIM_SECONDS
            <= time.time()
        ):
            result["phase"] = "stale"
    return result


def enable(binding_id, body, account):
    with database() as db:
        binding = one(db, "tunnel_bindings", binding_id)
        if not ready(db):
            raise HTTPException(
                503, "سرویس پایش و کلاینت آزمون باید روی میزبان پنل فعال باشند"
            )
        check = one(db, "tunnel_checks", body.check_id)
        now = int(time.time())
        if (
            check["binding_id"] != binding_id
            or check["phase"] != "succeeded"
            or check["expires"] <= now
            or check["source_revision"] != binding["source_revision"]
            or check["job_id"] != binding["job_id"]
            or not bindings.matches(db, binding)
            or binding["phase"] != "succeeded"
            or endpoints._client(db, binding, check["device_id"])[1]
            != check["device_revision"]
        ):
            raise HTTPException(
                409, "ابتدا پذیرش تازه و انتشار همین محدوده را انجام دهید"
            )
        published = list(
            db.execute(
                "SELECT inbound_id,check_id,expires FROM tunnel_endpoints WHERE binding_id=?",
                (binding_id,),
            )
        )
        if {p["inbound_id"] for p in published} != set(
            json.loads(check["inbound_ids"])
        ) or any(
            p["check_id"] != check["id"] or p["expires"] <= now for p in published
        ):
            raise HTTPException(
                409, "آدرس‌های منتشرشده باید دقیقاً متعلق به این آزمون باشند"
            )
        if (
            db.execute(
                "SELECT COUNT(*) FROM tunnel_monitors WHERE enabled=1 AND binding_id<>?",
                (binding_id,),
            ).fetchone()[0]
            >= MAX_MONITORS
        ):
            raise HTTPException(409, "ظرفیت پایش هم‌زمان پر شده است")
        fence(db, binding_id, withdraw_endpoints=False)
        values = (
            binding_id,
            uuid.uuid4().hex,
            account["username"],
            check["device_id"],
            check["device_revision"],
            binding["source_revision"],
            binding["job_id"],
            check["inbound_ids"],
            tunnel_probe.configuration_revision(),
            body.interval_seconds,
            max(now, check["finished"] + body.interval_seconds),
            check["finished"],
            check["id"],
            now,
            now,
        )
        db.execute("DELETE FROM tunnel_monitors WHERE binding_id=?", (binding_id,))
        db.execute(
            "INSERT INTO tunnel_monitors(binding_id,enabled,revision,actor,device_id,device_revision,"
            "source_revision,job_id,inbound_ids,probe_revision,interval_seconds,next_run,phase,"
            "last_success,last_check_id,created,updated) VALUES(?,1,?,?,?,?,?,?,?,?,?,?,'healthy',?,?,?,?)",
            values,
        )
        audit(db, account["username"], "tunnel.monitor.enable", binding_id)
        return metadata(db, binding_id)


def disable(binding_id, account):
    with database() as db:
        one(db, "tunnel_bindings", binding_id)
        fence(db, binding_id)
        audit(db, account["username"], "tunnel.monitor.disable", binding_id)
        return metadata(db, binding_id)


def guard_claim(db, claim, binding):
    row = _row(db, binding["id"])
    if (
        not row
        or not row["enabled"]
        or row["revision"] != claim["revision"]
        or row["run_id"] != claim["run_id"]
        or row["claim_until"] <= time.time()
        or not ready(db, claim["instance_id"])
    ):
        raise HTTPException(409, "اجرای پایش لغو یا منقضی شده است")
    _scope(db, row, binding)
    return row


def succeeded(db, claim, check_id):
    now = int(time.time())
    db.execute(
        "UPDATE tunnel_monitors SET phase='healthy',last_finished=?,last_success=?,last_check_id=?,"
        "failures=0,error_code=NULL,run_id=NULL,instance_id=NULL,claim_until=NULL,next_run=?,updated=? "
        "WHERE binding_id=? AND revision=? AND run_id=?",
        (
            now,
            now,
            check_id,
            now + claim["interval_seconds"],
            now,
            claim["binding_id"],
            claim["revision"],
            claim["run_id"],
        ),
    )


def failed(claim, error):
    with database() as db:
        row = _row(db, claim["binding_id"])
        if (
            not row
            or not row["enabled"]
            or row["revision"] != claim["revision"]
            or row["run_id"] != claim["run_id"]
        ):
            return  # A late callback cannot withdraw a newer manual publication.
        withdraw(db, row["binding_id"])
        now = int(time.time())
        failures = min(row["failures"] + 1, 10)
        db.execute(
            "UPDATE tunnel_monitors SET phase='unhealthy',last_finished=?,failures=?,error_code=?,"
            "run_id=NULL,instance_id=NULL,claim_until=NULL,next_run=?,updated=? WHERE binding_id=?",
            (
                now,
                failures,
                error,
                now + min(3600, row["interval_seconds"] * 2 ** (failures - 1)),
                now,
                row["binding_id"],
            ),
        )
        audit(db, row["actor"], "tunnel.monitor.failure", row["binding_id"])


def claim_due(instance_id):
    with database() as db:
        if not ready(db, instance_id):
            return None
        now = int(time.time())
        # Interrupted probes remain globally exclusive until their bounded deadline.
        db.execute(
            "UPDATE tunnel_checks SET phase='failed',error_code='probe_interrupted' WHERE phase='running' AND started<?",
            (now - CLAIM_SECONDS,),
        )
        if db.execute("SELECT 1 FROM tunnel_checks WHERE phase='running'").fetchone():
            return None
        if db.execute(
            "SELECT 1 FROM tunnel_monitors WHERE enabled=1 AND run_id IS NOT NULL AND claim_until>?",
            (now,),
        ).fetchone():
            return None
        for row in db.execute(
            "SELECT * FROM tunnel_monitors WHERE enabled=1 ORDER BY next_run,binding_id"
        ).fetchall():
            binding = one(db, "tunnel_bindings", row["binding_id"])
            try:
                _scope(db, row, binding)
            except (HTTPException, tunnel_probe.ProbeError, ValueError):
                fence(db, row["binding_id"], error="monitor_scope_changed")
                continue
            if row["run_id"]:
                if row["claim_until"] > now:
                    return None
                withdraw(db, row["binding_id"])
                db.execute(
                    "UPDATE tunnel_monitors SET run_id=NULL,instance_id=NULL,claim_until=NULL,phase='unhealthy',error_code='monitor_interrupted' WHERE binding_id=?",
                    (row["binding_id"],),
                )
            if row["next_run"] > now:
                continue
            run_id = uuid.uuid4().hex
            db.execute(
                "UPDATE tunnel_monitors SET run_id=?,instance_id=?,claim_until=?,phase='checking',last_started=?,updated=? WHERE binding_id=?",
                (run_id, instance_id, now + CLAIM_SECONDS, now, now, row["binding_id"]),
            )
            return dict(_row(db, row["binding_id"]))
    return None


def run_due(instance_id, controller, *, stopping=lambda: False):
    claim = claim_due(instance_id)
    if not claim:
        return False
    account = {"username": claim["actor"]}
    try:
        check = endpoints.verify(
            claim["binding_id"],
            endpoints.VerifyInput(
                device_id=claim["device_id"],
                inbound_ids=json.loads(claim["inbound_ids"]),
            ),
            account,
            controller,
            monitor_claim=claim,
        )
        if check["phase"] != "succeeded":
            failed(claim, check["error_code"] or "monitor_probe_failed")
        elif stopping():
            failed(claim, "monitor_stopped")
        else:
            endpoints.publish(
                claim["binding_id"],
                endpoints.PublishInput(check_id=check["id"], confirm_publish=True),
                account,
                controller,
                monitor_claim=claim,
            )
    except Exception:
        # No upstream diagnostics, paths, targets or credentials are persisted.
        failed(claim, "monitor_guard_failed")
    return True
