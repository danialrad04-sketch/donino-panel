"""Read-only doctor-dns snapshots and reversible, disabled account staging.

Source smart-DNS bytes, passwords, wallet and IP claims are never silently
converted into VPN/DNS-query entitlements. Source sessions are never reused.
"""

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .db import database, initialize, audit
from .gaming_catalog import SOURCE_REVISION, catalog
from .dns_policy import DNSRule
from .dns_service import canonical_address
from .ops import backup
from .secrets import seal

TABLES = {
    "users",
    "ips",
    "templates",
    "template_services",
    "template_domains_off",
    "custom_domains",
    "transactions",
    "settings",
    "ip_counters",
}
OMITTED = {"admin_sessions", "panel_sessions", "metrics"}
MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100_000


def encoded(value):
    return (
        {"$bytes": base64.b64encode(value).decode()}
        if isinstance(value, bytes)
        else value
    )


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def timestamp(value, *, required=False):
    if value is None or value == "":
        if required:
            raise ValueError("Source timestamp is missing")
        return None
    if not isinstance(value, str):
        raise ValueError("Source timestamp must be text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # Older doctor-dns timestamps may omit the timezone; its clock is UTC.
    parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    result = int(parsed.timestamp())
    if not 0 < result <= 32_503_680_000:
        raise ValueError("Source timestamp is outside the supported range")
    return result


def integer(row, name, *, minimum=0):
    value = row.get(name)
    if type(value) is not int or not minimum <= value <= 9_000_000_000_000_000:
        raise ValueError(f"Invalid source integer: {name}")
    return value


def inspect_source(path, *, revision=SOURCE_REVISION):
    if revision != SOURCE_REVISION:
        raise ValueError("Unsupported doctor-dns format revision")
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Source must be a regular SQLite file of at most 64 MiB")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as source:
        source.execute("PRAGMA trusted_schema=OFF")
        pages = source.execute("PRAGMA page_count").fetchone()[0]
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        if pages * page_size > MAX_BYTES:
            raise ValueError("Source exceeds the snapshot limit")
        with sqlite3.connect(":memory:") as db:
            deadline = time.monotonic() + 15

            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise ValueError(
                        "Source snapshot timed out; pause source writes and retry"
                    )
                if total * page_size > MAX_BYTES:
                    raise ValueError("Growing source exceeds the snapshot limit")

            source.backup(db, pages=256, progress=progress)
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Source database integrity failed")
            schema = db.execute(
                "SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','view')"
            ).fetchall()
            names = {row[0] for row in schema}
            if not TABLES <= names or names - TABLES - OMITTED:
                raise ValueError(
                    "Unsupported/missing source tables; upgrade the source format explicitly"
                )
            for name, kind, sql in schema:
                if kind != "table" or not sql.lstrip().upper().startswith(
                    "CREATE TABLE"
                ):
                    raise ValueError("Source views and virtual tables are refused")
            db.row_factory = sqlite3.Row
            tables, counts, total_rows = {}, {}, 0
            for name in sorted(TABLES | (names & OMITTED)):
                count = db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                counts[name] = count
                if name in OMITTED:
                    continue
                total_rows += count
                if total_rows > MAX_ROWS:
                    raise ValueError("Source exceeds the row limit")
                rows = [
                    {k: encoded(v) for k, v in dict(r).items()}
                    for r in db.execute(f'SELECT * FROM "{name}"')
                ]
                tables[name] = sorted(rows, key=canonical)
    validate_source(tables)
    payload = {
        "format": "doctor-dns-staging-v1",
        "revision": revision,
        "tables": tables,
    }
    raw = canonical(payload)
    if len(raw.encode()) > 2 * MAX_BYTES:
        raise ValueError("Expanded source exceeds the archive limit")
    summary = {
        "counts": {k: v for k, v in counts.items() if k in TABLES},
        "omitted": {k: v for k, v in counts.items() if k in OMITTED},
        "quota_bytes": sum(u["quota_bytes"] for u in tables["users"]),
        "used_bytes": sum(u["used_bytes"] for u in tables["users"]),
        "activation": "staged-disabled",
        "ip_leases_activated": 0,
        "wallets_activated": 0,
        "passwords_activated": 0,
    }
    return {
        "fingerprint": hashlib.sha256(raw.encode()).hexdigest(),
        "summary": summary,
        "payload": payload,
    }


def validate_source(tables):
    users = {}
    templates = {integer(t, "id", minimum=1): t for t in tables["templates"]}
    if len(templates) != len(tables["templates"]):
        raise ValueError("Duplicate template identity")
    if any(
        type(t.get("is_default")) is not int
        or t["is_default"] not in (0, 1)
        or not isinstance(t.get("name"), str)
        or not t["name"]
        for t in templates.values()
    ):
        raise ValueError("Invalid source template metadata")
    if sum(bool(t.get("is_default")) for t in templates.values()) > 1:
        raise ValueError("Source has more than one default template")
    for row in tables["users"]:
        uid = integer(row, "id", minimum=1)
        if uid in users:
            raise ValueError("Duplicate user identity")
        users[uid] = row
        for name in ("quota_bytes", "used_bytes", "wallet", "speed_kbps"):
            integer(row, name)
        integer(row, "max_ips", minimum=1)
        if row.get("status") not in (
            "active",
            "disabled",
            "expired",
            "over_quota",
            "pending",
        ):
            raise ValueError("Unknown source account status")
        if row.get("quota_mode") not in ("monthly", "oneoff"):
            raise ValueError("Unknown source quota period")
        for name in ("created_at", "expires_at", "quota_reset_at"):
            timestamp(row.get(name), required=name == "created_at")
        if row.get("template_id") is not None and row["template_id"] not in templates:
            raise ValueError("User references an unknown template")
        password, salt = row.get("password_hash"), row.get("password_salt")
        if password or salt:
            if (
                not isinstance(password, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", password)
                or not isinstance(salt, str)
                or not re.fullmatch(r"[0-9a-fA-F]{32}", salt)
            ):
                raise ValueError(
                    "Unknown password hash format; no credentials were imported"
                )
    seen_ips = set()
    for row in tables["ips"]:
        ip = str(canonical_address(row["ip"]))
        if row["user_id"] not in users or ip in seen_ips:
            raise ValueError("Unknown IP owner or shared source-IP ownership conflict")
        seen_ips.add(ip)
        integer(row, "last_counter")
    known = {(s["key"], g["key"]) for s in catalog()["services"] for g in s["groups"]}
    for row in tables["template_services"]:
        if (
            row["template_id"] not in templates
            or (row["service_key"], row["group_key"]) not in known
        ):
            raise ValueError(
                "Unknown template service/group; update the catalog explicitly"
            )
    for row in tables["template_domains_off"]:
        if row["template_id"] not in templates:
            raise ValueError("Unknown excluded-domain template")
        DNSRule(domain=row["domain"], action="allow")
    for row in tables["custom_domains"]:
        DNSRule(domain=row["domain"], action="allow")
    for row in tables["transactions"]:
        if row["user_id"] not in users:
            raise ValueError("Receipt/transaction references an unknown user")
    for row in tables["ip_counters"]:
        canonical_address(row["ip"])
        integer(row, "last_counter")


def guard_hash(db, uid):
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        raise ValueError("Imported user is missing")
    devices = [
        dict(r)
        for r in db.execute("SELECT * FROM devices WHERE user_id=? ORDER BY id", (uid,))
    ]
    relations = {}
    for table in ("user_nodes", "usage_periods", "budget_leases", "dns_accounts"):
        relations[table] = sorted(
            [
                dict(r)
                for r in db.execute(f"SELECT * FROM {table} WHERE user_id=?", (uid,))
            ],
            key=canonical,
        )
    relations["counters"] = sorted(
        [
            dict(r)
            for r in db.execute(
                "SELECT c.* FROM counters c JOIN devices d ON d.id=c.device_id WHERE d.user_id=?",
                (uid,),
            )
        ],
        key=canonical,
    )
    return hashlib.sha256(
        canonical(
            {"user": dict(user), "devices": devices, "relations": relations}
        ).encode()
    ).hexdigest()


def existing(db, source_instance, fingerprint):
    row = db.execute(
        "SELECT * FROM doctor_imports WHERE source_instance=?", (source_instance,)
    ).fetchone()
    if not row:
        return None
    if row["fingerprint"] != fingerprint or row["state"] != "staged":
        raise ValueError(
            "This source instance was already used or reverted; changed snapshots require an explicit migration"
        )
    return {"id": row["id"], "state": row["state"], "already_staged": True}


def stage(snapshot, source_instance, expected, backup_path):
    source_instance = str(uuid.UUID(source_instance))
    if snapshot["fingerprint"] != expected:
        raise ValueError(
            "Source changed since inspection; inspect again before applying"
        )
    initialize()
    with database() as db:
        previous = existing(db, source_instance, expected)
        if previous:
            return previous
    backup(backup_path)  # Failure aborts before imported records are created.
    encrypted = seal(canonical(snapshot["payload"]))
    job, now = str(uuid.uuid4()), int(time.time())
    tables = snapshot["payload"]["tables"]
    with database() as db:
        previous = existing(db, source_instance, expected)
        if previous:
            return previous
        db.execute(
            "INSERT INTO doctor_imports(id,source_instance,fingerprint,source_revision,state,summary,payload,backup_path,created) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                job,
                source_instance,
                expected,
                SOURCE_REVISION,
                "staged",
                canonical(snapshot["summary"]),
                encrypted,
                str(Path(backup_path).resolve()),
                now,
            ),
        )
        for row in tables["users"]:
            uid, secret = str(uuid.uuid4()), str(uuid.uuid4())
            label = str(row.get("username") or row.get("first_name") or "user")[:35]
            name = f"doctor-{source_instance[:8]}-{row['id']}-{label}"
            created = timestamp(row["created_at"], required=True)
            expires = timestamp(row.get("expires_at"))
            db.execute(
                "INSERT INTO users(id,credential,name,enabled,quota,expires,token,created) VALUES(?,?,?,0,0,?,?,?)",
                (uid, secret, name, expires, secrets.token_urlsafe(32), created),
            )
            db.execute(
                "INSERT INTO devices(id,user_id,name,secret,enabled,is_default,created) VALUES(?,?,?,?,0,1,?)",
                (uid, uid, "default", secret, created),
            )
            db.execute(
                "INSERT INTO doctor_import_users VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    job,
                    row["id"],
                    uid,
                    row["quota_bytes"],
                    row["used_bytes"],
                    row["status"],
                    row["quota_mode"],
                    timestamp(row.get("quota_reset_at")),
                    expires,
                    guard_hash(db, uid),
                ),
            )
        all_groups = [
            {"service": s["key"], "group": g["key"]}
            for s in catalog()["services"]
            for g in s["groups"]
        ]
        for row in tables["templates"]:
            groups = (
                all_groups
                if row["is_default"]
                else [
                    {"service": g["service_key"], "group": g["group_key"]}
                    for g in tables["template_services"]
                    if g["template_id"] == row["id"]
                ]
            )
            excluded = [
                d["domain"]
                for d in tables["template_domains_off"]
                if d["template_id"] == row["id"]
            ]
            db.execute(
                "INSERT INTO doctor_import_templates VALUES(?,?,?,?,?,?,?)",
                (
                    job,
                    row["id"],
                    row["name"],
                    int(bool(row["is_default"])),
                    canonical(groups),
                    canonical(excluded),
                    canonical([d["domain"] for d in tables["custom_domains"]]),
                ),
            )
        audit(db, "local-cli", "doctor.import.staged", job)
    return {
        "id": job,
        "state": "staged",
        "already_staged": False,
        "summary": snapshot["summary"],
    }


def rollback(job, backup_path):
    def unchanged(db):
        row = db.execute(
            "SELECT state FROM doctor_imports WHERE id=?", (job,)
        ).fetchone()
        if not row:
            raise ValueError("Unknown import")
        if row["state"] == "rolled_back":
            return None
        users = db.execute(
            "SELECT * FROM doctor_import_users WHERE import_id=?", (job,)
        ).fetchall()
        if any(guard_hash(db, row["user_id"]) != row["guard_hash"] for row in users):
            raise ValueError(
                "Imported user or related data changed; rollback refused without deleting anything"
            )
        return users

    with database() as db:
        if unchanged(db) is None:
            return {"id": job, "state": "rolled_back"}
    backup(backup_path)
    with database() as db:
        users = unchanged(db)
        if users is None:
            return {"id": job, "state": "rolled_back"}
        db.execute("DELETE FROM doctor_import_users WHERE import_id=?", (job,))
        for row in users:
            db.execute("DELETE FROM users WHERE id=?", (row["user_id"],))
        db.execute("DELETE FROM doctor_import_templates WHERE import_id=?", (job,))
        db.execute(
            "UPDATE doctor_imports SET state='rolled_back',reverted=? WHERE id=?",
            (int(time.time()), job),
        )
        audit(db, "local-cli", "doctor.import.rolled-back", job)
    return {"id": job, "state": "rolled_back"}
