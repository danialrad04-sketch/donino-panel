"""Conservative shared-quota reservations, not an exact-byte billing promise.

Expired, unreconciled grants stay reserved. A partition cannot make the same
unreported credit available to another node. Nodes meter samples locally; byte
overshoot remains sampling/rate dependent and is recorded rather than discarded.
"""

import time
import uuid

from fastapi import HTTPException

from .db import audit

QUANTUM = 8 * 1024 * 1024
TTL = 60


def reserve_total(db, uid, period_no):
    return db.execute(
        "SELECT COALESCE(SUM(CASE WHEN granted>spent THEN granted-spent ELSE 0 END),0) FROM budget_leases WHERE user_id=? AND period_no=? AND closed=0",
        (uid, period_no),
    ).fetchone()[0]


def allocations(db, node, clients, instance, *, now=None):
    now = int(time.time()) if now is None else now
    grants = []
    has_endpoint = (
        db.execute(
            "SELECT 1 FROM inbounds WHERE node_id=? AND enabled=1 LIMIT 1",
            (node["id"],),
        ).fetchone()
        is not None
    )
    by_user = {}
    for client in clients:
        if client["quota_mode"] == "lease":
            by_user.setdefault(client["user_id"], []).append(client)
    for uid, devices in by_user.items():
        if (
            node["auth_mode"] != "mtls"
            or not has_endpoint
            or not instance
            or not any(client["eligible"] for client in devices)
        ):
            for client in devices:
                client["eligible"] = False
            continue
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        row = db.execute(
            "SELECT * FROM budget_leases WHERE user_id=? AND node_id=? AND period_no=? AND instance=?",
            (uid, node["id"], user["period_no"], instance),
        ).fetchone()
        available = max(
            0, user["quota"] - user["used"] - reserve_total(db, uid, user["period_no"])
        )
        node_count = db.execute(
            """SELECT COUNT(*) FROM nodes n WHERE n.enabled=1 AND n.auth_mode='mtls'
            AND (?='all' OR EXISTS(SELECT 1 FROM user_nodes un WHERE un.user_id=? AND un.node_id=n.id))""",
            (user["node_mode"], uid),
        ).fetchone()[0]
        quantum = min(
            QUANTUM,
            max(1, (user["quota"] + max(1, node_count) - 1) // max(1, node_count)),
        )
        if row is None and available:
            lease_id = str(uuid.uuid4())
            grant = min(quantum, available)
            db.execute(
                "INSERT INTO budget_leases(id,user_id,node_id,period_no,instance,granted,expires,created,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    lease_id,
                    uid,
                    node["id"],
                    user["period_no"],
                    instance,
                    grant,
                    now + TTL,
                    now,
                    now,
                ),
            )
            available -= grant
            row = db.execute(
                "SELECT * FROM budget_leases WHERE id=?", (lease_id,)
            ).fetchone()
        if row and not row["closed"]:
            remaining = max(0, row["granted"] - row["spent"])
            addition = (
                min(quantum - remaining, available)
                if remaining < max(1, quantum // 4)
                else 0
            )
            expires = min(now + TTL, user["expires"] or now + TTL)
            db.execute(
                "UPDATE budget_leases SET granted=granted+?,expires=?,updated=? WHERE id=?",
                (max(0, addition), expires, now, row["id"]),
            )
            row = db.execute(
                "SELECT * FROM budget_leases WHERE id=?", (row["id"],)
            ).fetchone()
        if not row or row["closed"] or row["spent"] >= row["granted"]:
            for client in devices:
                client["eligible"] = False
            continue
        grants.append(
            {
                "id": row["id"],
                "user_id": uid,
                "period_no": row["period_no"],
                "granted": row["granted"],
                "spent": row["spent"],
                "expires": row["expires"],
                "devices": [client["id"] for client in devices if client["eligible"]],
            }
        )
    return grants


def account_budget(db, node_id, user, old, sample, period_no, delta, now):
    lease_id = sample.lease_id
    if old and old["lease_id"] != lease_id:
        raise HTTPException(
            409, "A process/device counter cannot change its budget lease"
        )
    if not lease_id:
        if user["quota_mode"] == "lease":
            raise HTTPException(
                409, "Shared-quota usage requires its allocated budget lease"
            )
        return
    lease = db.execute(
        "SELECT * FROM budget_leases WHERE id=? AND node_id=? AND user_id=? AND period_no=?",
        (lease_id, node_id, user["id"], period_no),
    ).fetchone()
    if not lease or lease["closed"] and delta > 0:
        raise HTTPException(409, "Unknown, closed or mismatched budget lease")
    db.execute(
        "UPDATE budget_leases SET spent=spent+?,updated=? WHERE id=?",
        (delta, now, lease_id),
    )
    if lease["spent"] <= lease["granted"] < lease["spent"] + delta:
        audit(db, "node:" + node_id, "budget.sampled-overshoot", lease_id)


def close_budgets(db, node, instance, lease_ids, now):
    if not lease_ids:
        return
    if not instance:
        raise HTTPException(422, "Closing a grant requires its supervisor instance")
    for lease_id in set(lease_ids):
        row = db.execute(
            "SELECT * FROM budget_leases WHERE id=? AND node_id=? AND instance=?",
            (lease_id, node["id"], instance),
        ).fetchone()
        if not row:
            raise HTTPException(409, "Cannot close another instance's budget")
        if not row["closed"]:
            db.execute(
                "UPDATE budget_leases SET closed=1,updated=? WHERE id=?",
                (now, lease_id),
            )
            audit(db, "node:" + node["id"], "budget.closed", lease_id)


def summaries(db):
    now = int(time.time())
    rows = db.execute(
        """SELECT b.user_id,b.period_no,
        SUM(CASE WHEN b.closed=0 AND b.granted>b.spent THEN b.granted-b.spent ELSE 0 END) AS reserved,
        SUM(CASE WHEN b.closed=0 AND b.expires<=? AND b.granted>b.spent THEN b.granted-b.spent ELSE 0 END) AS unreconciled
        FROM budget_leases b JOIN users u ON u.id=b.user_id AND u.period_no=b.period_no
        GROUP BY b.user_id,b.period_no""",
        (now,),
    ).fetchall()
    return {
        (row["user_id"], row["period_no"]): {
            "budget_reserved": row["reserved"],
            "budget_unreconciled": row["unreconciled"],
        }
        for row in rows
    }
