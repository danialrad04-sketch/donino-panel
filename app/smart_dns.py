"""Smart DNS routing, source-lease admission and a separate relay byte ledger."""

import ipaddress
import json
import os
import time
import uuid

import dns.name
from fastapi import HTTPException

from .db import database
from .deps import one
from .dns_policy import rule_for
from .dns_service import account_row, canonical_address
from .secrets import unseal


def enabled():
    return os.environ.get("DONINO_SMART_DNS", "") == "1"


def front_addresses():
    values = []
    for raw in os.environ.get("DONINO_SMART_DNS_IPS", "").split(","):
        if not raw.strip():
            continue
        ip = ipaddress.ip_address(raw.strip())
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or "%" in raw:
            raise ValueError("Invalid Smart DNS front address")
        values.append(str(ip))
    return sorted(set(values))[:8]


def candidates(db, rule):
    values, now = [], int(time.time())
    for exit_id in rule["exit_ids"]:
        row = db.execute("SELECT * FROM smart_exits WHERE id=?", (exit_id,)).fetchone()
        if (
            row
            and row["mode"] == "active"
            and not (
                row["healthy"] == 0 and row["checked"] and row["checked"] > now - 10
            )
        ):
            values.append(dict(row))
    return values


def gateway_ready(db):
    row = db.execute("SELECT * FROM smart_gateway WHERE id=1").fetchone()
    return bool(
        row
        and row["lease_until"] > time.time()
        and json.loads(row["addresses"]) == front_addresses()
    )


def heartbeat(instance):
    now = int(time.time())
    with database() as db:
        row = db.execute("SELECT * FROM smart_gateway WHERE id=1").fetchone()
        if row and row["instance_id"] != instance and row["lease_until"] > now:
            raise RuntimeError("Another Smart DNS gateway holds the lease")
        db.execute(
            "INSERT INTO smart_gateway(id,instance_id,addresses,lease_until) VALUES(1,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,addresses=excluded.addresses,lease_until=excluded.lease_until",
            (instance, json.dumps(front_addresses()), now + 10),
        )


def validate_routes(db, rules):
    for rule in rules:
        for exit_id in rule.exit_ids:
            one(db, "smart_exits", exit_id)


def route_rules(account, source_ip=None):
    rules = json.loads(account["rules"])
    if not any(rule["action"] == "route" for rule in rules):
        return rules
    ips = front_addresses() if enabled() else []
    try:
        source_ip = str(canonical_address(source_ip or ""))
    except ValueError:
        source_ip = ""
    with database() as db:
        period = db.execute(
            "SELECT relay_up+relay_down FROM dns_periods WHERE account_id=? AND period_no=?",
            (account["id"], account["period_no"]),
        ).fetchone()
        has_quota = bool(period) and (
            not account["relay_limit"] or period[0] < account["relay_limit"]
        )
        leased = db.execute(
            "SELECT 1 FROM dns_ip_leases WHERE account_id=? AND ip=? AND expires>?",
            (account["id"], source_ip, int(time.time())),
        ).fetchone()
        for rule in rules:
            if rule["action"] == "route":
                ready = bool(
                    account["relay_enabled"]
                    and has_quota
                    and ips
                    and leased
                    and gateway_ready(db)
                    and candidates(db, rule)
                )
                rule.update(
                    action="rewrite" if ready else "unavailable",
                    addresses=ips if ready else [],
                    ttl=30,
                )
    return rules


def _account(db, source, account_id=None):
    if not enabled():
        raise HTTPException(403, "Smart DNS is disabled")
    if not gateway_ready(db):
        raise HTTPException(503, "Smart DNS gateway lease is not current")
    account = account_row(db, source_ip=source)
    if not account["relay_enabled"] or (account_id and account["id"] != account_id):
        raise HTTPException(
            403, "Smart DNS source ownership changed or service disabled"
        )
    return account


def _rule(account, host):
    rule = rule_for(dns.name.from_text(host), json.loads(account["rules"]))
    if not rule or rule["action"] != "route":
        raise HTTPException(403, "Domain is not routed by this account")
    return rule


def health(exit_id, revision, ok, latency=0):
    with database() as db:
        db.execute(
            "UPDATE smart_exits SET healthy=?,checked=?,latency=?,error_code=? WHERE id=? AND revision=?",
            (
                int(ok),
                int(time.time()),
                int(latency),
                None if ok else "tls_or_connect_failed",
                exit_id,
                revision,
            ),
        )


def admit(source, host):
    now, sid = int(time.time()), uuid.uuid4().hex
    with database() as db:
        account = _account(db, source)
        rule = _rule(account, host)
        exits = candidates(db, rule)
        if not exits:
            raise HTTPException(503, "No eligible exit")
        db.execute(
            "UPDATE smart_sessions SET closed=?,error_code='lease_expired' WHERE closed IS NULL AND lease_until<=?",
            (now, now),
        )
        total = db.execute(
            "SELECT COUNT(*) FROM smart_sessions WHERE closed IS NULL"
        ).fetchone()[0]
        active = db.execute(
            "SELECT COUNT(*) FROM smart_sessions WHERE account_id=? AND closed IS NULL",
            (account["id"],),
        ).fetchone()[0]
        used = db.execute(
            "SELECT relay_up+relay_down FROM dns_periods WHERE account_id=? AND period_no=?",
            (account["id"], account["period_no"]),
        ).fetchone()[0]
        if total >= 256 or active >= account["relay_connections"]:
            raise HTTPException(429, "Smart DNS connection limit")
        if account["relay_limit"] and used >= account["relay_limit"]:
            raise HTTPException(403, "Smart DNS byte quota exhausted")
        if db.execute("SELECT COUNT(*) FROM smart_sessions").fetchone()[0] >= 100000:
            raise HTTPException(503, "Smart DNS history capacity reached")
        db.execute(
            "INSERT INTO smart_sessions(id,account_id,period_no,created,updated,lease_until) VALUES(?,?,?,?,?,?)",
            (sid, account["id"], account["period_no"], now, now, now + 10),
        )
        db.execute(
            "UPDATE dns_periods SET relay_sessions=relay_sessions+1 WHERE account_id=? AND period_no=?",
            (account["id"], account["period_no"]),
        )
    return {
        "id": sid,
        "account_id": account["id"],
        "period_no": account["period_no"],
        "revision": account["revision"],
        "source": source,
        "host": host,
        "exits": exits,
    }


def selected(session, exit_id, revision):
    with database() as db:
        node = one(db, "smart_exits", exit_id)
        if node["mode"] != "active" or node["revision"] != revision:
            raise HTTPException(409, "Exit changed while connecting")
        db.execute(
            "UPDATE smart_sessions SET exit_id=? WHERE id=? AND closed IS NULL",
            (exit_id, session["id"]),
        )


def connecting(session):
    """Renew admission between bounded exit attempts without reserving bytes."""
    now = int(time.time())
    with database() as db:
        row = one(db, "smart_sessions", session["id"])
        account = _account(db, session["source"], session["account_id"])
        _rule(account, session["host"])
        if (
            row["closed"]
            or row["lease_until"] <= now
            or row["exit_id"]
            or account["period_no"] != session["period_no"]
            or account["revision"] != session["revision"]
        ):
            raise HTTPException(403, "Smart DNS admission changed")
        db.execute(
            "UPDATE smart_sessions SET updated=?,lease_until=? WHERE id=?",
            (now, now + 10, row["id"]),
        )


def charge(session, direction, size=0):
    if direction not in ("up", "down") or not 0 <= size <= 32768:
        raise ValueError("Invalid relay byte reservation")
    now = int(time.time())
    with database() as db:
        row = one(db, "smart_sessions", session["id"])
        account = _account(db, session["source"], session["account_id"])
        rule = _rule(account, session["host"])
        node = db.execute(
            "SELECT mode,revision FROM smart_exits WHERE id=?", (row["exit_id"],)
        ).fetchone()
        if (
            row["closed"]
            or row["lease_until"] <= now
            or account["period_no"] != session["period_no"]
            or account["revision"] != session["revision"]
            or not node
            or node["mode"] not in ("active", "drain")
            or node["revision"] != session["exit_revision"]
            or row["exit_id"] not in rule["exit_ids"]
        ):
            raise HTTPException(403, "Smart DNS session authorization changed")
        used = db.execute(
            "SELECT relay_up+relay_down FROM dns_periods WHERE account_id=? AND period_no=?",
            (account["id"], session["period_no"]),
        ).fetchone()[0]
        if account["relay_limit"] and used + size > account["relay_limit"]:
            raise HTTPException(403, "Smart DNS byte quota exhausted")
        counter = "uploaded" if direction == "up" else "downloaded"
        db.execute(
            f"UPDATE smart_sessions SET {counter}={counter}+?,updated=?,lease_until=? WHERE id=?",
            (size, now, now + 10, row["id"]),
        )
        db.execute(
            f"UPDATE dns_periods SET relay_{direction}=relay_{direction}+? WHERE account_id=? AND period_no=?",
            (size, account["id"], session["period_no"]),
        )


def finish(session, error=None):
    with database() as db:
        updated = db.execute(
            "UPDATE smart_sessions SET closed=?,error_code=? WHERE id=? AND closed IS NULL",
            (int(time.time()), error, session["id"]),
        )
        if updated.rowcount and error:
            db.execute(
                "UPDATE dns_periods SET relay_errors=relay_errors+1 WHERE account_id=? AND period_no=?",
                (session["account_id"], session["period_no"]),
            )


def private_exit(row):
    return {**row, "password": unseal(row["password"])}


def invalidate_restored(db):
    db.execute("DELETE FROM smart_gateway")
    db.execute(
        "UPDATE smart_exits SET mode='disabled',healthy=NULL,checked=NULL,error_code='restored'"
    )
    db.execute("UPDATE dns_accounts SET relay_enabled=0")
    db.execute(
        "UPDATE smart_sessions SET closed=?,error_code='restored' WHERE closed IS NULL",
        (int(time.time()),),
    )
