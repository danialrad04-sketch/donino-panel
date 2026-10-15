"""Device identities, explicit assignments and period-aware connection views."""

import time
import uuid

PROTOCOLS = ("vless", "vmess", "trojan")


def ensure_identity(db, user, *, owner=None):
    """Idempotent legacy backfill, also used for newly created users."""
    if db.execute("SELECT 1 FROM user_state WHERE user_id=?", (user["id"],)).fetchone():
        return
    uid, period = user["id"], str(uuid.uuid4())
    db.execute(
        "INSERT INTO devices(id,user_id,name,created,legacy) VALUES(?,?,?,?,1)",
        (uid, uid, "Primary", user["created"]),
    )
    for protocol in PROTOCOLS:
        db.execute(
            "INSERT INTO credentials(id,device_id,protocol,secret) VALUES(?,?,?,?)",
            (str(uuid.uuid4()), uid, protocol, user["credential"]),
        )
    db.execute(
        "INSERT INTO user_periods(id,user_id,started,uploaded,downloaded,legacy_used,reason) VALUES(?,?,?,?,?,?,?)",
        (
            period,
            uid,
            int(time.time()),
            user["uploaded"],
            user["downloaded"],
            user["legacy_used"],
            "created",
        ),
    )
    db.execute(
        "INSERT INTO user_state(user_id,period_id,owner_username) VALUES(?,?,?)",
        (uid, period, owner),
    )


def connection_users(db, node_id=None, user_id=None):
    where, params = [], []
    if user_id:
        where.append("u.id=?")
        params.append(user_id)
    if node_id:
        policy = db.execute(
            "SELECT mode FROM node_policy WHERE node_id=?", (node_id,)
        ).fetchone()
        if policy and policy["mode"] == "selected":
            where.append("u.id IN (SELECT user_id FROM user_nodes WHERE node_id=?)")
            params.append(node_id)
    query = (
        "SELECT u.* FROM users u"
        + (" WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY u.id"
    )
    result = []
    for row in db.execute(query, tuple(params)):
        user = dict(row)
        # Compatibility for users inserted by older scripts after migration.
        ensure_identity(db, user)
        state = db.execute(
            "SELECT period_id FROM user_state WHERE user_id=?", (user["id"],)
        ).fetchone()
        for device in db.execute(
            "SELECT * FROM devices WHERE user_id=? AND enabled=1 ORDER BY id",
            (user["id"],),
        ):
            if device["expires"] and device["expires"] <= time.time():
                continue
            item = dict(user)
            item.update(
                id=device["id"],
                user_id=user["id"],
                device_name=device["name"],
                period_id=state["period_id"],
            )
            item["credentials"] = {
                r["protocol"]: r["secret"]
                for r in db.execute(
                    "SELECT protocol,secret FROM credentials WHERE device_id=?",
                    (device["id"],),
                )
            }
            result.append(item)
    return result


def permitted_inbounds(db, user_id):
    return list(
        db.execute(
            "SELECT i.*,n.host,n.name node_name,n.enabled node_enabled FROM inbounds i JOIN nodes n ON n.id=i.node_id "
            "LEFT JOIN node_policy p ON p.node_id=n.id WHERE (p.mode IS NULL OR p.mode='all' OR "
            "EXISTS (SELECT 1 FROM user_nodes a WHERE a.node_id=n.id AND a.user_id=?)) ORDER BY i.id",
            (user_id,),
        )
    )


def profile_sets(db, user, device_id=None):
    from .core import profiles

    links, proxies = [], []
    inbounds = permitted_inbounds(db, user["id"])
    for device in connection_users(db, user_id=user["id"]):
        if device_id and device["id"] != device_id:
            continue
        raw, clash = profiles(device, inbounds)
        links.extend(raw)
        proxies.extend(clash["proxies"])
    return links, {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "Donino",
                "type": "select",
                "proxies": [p["name"] for p in proxies] or ["DIRECT"],
            }
        ],
        "rules": ["MATCH,Donino"],
    }


def reset_period(db, uid, reason="reset"):
    db.lock("user:" + uid)
    now, period = int(time.time()), str(uuid.uuid4())
    state = db.execute(
        "SELECT period_id FROM user_state WHERE user_id=?", (uid,)
    ).fetchone()
    if state:
        db.execute(
            "UPDATE user_periods SET ended=? WHERE id=?", (now, state["period_id"])
        )
    db.execute(
        "INSERT INTO user_periods(id,user_id,started,reason) VALUES(?,?,?,?)",
        (period, uid, now, reason),
    )
    if state:
        db.execute("UPDATE user_state SET period_id=? WHERE user_id=?", (period, uid))
    db.execute(
        "UPDATE users SET used=0,uploaded=0,downloaded=0,legacy_used=0 WHERE id=?",
        (uid,),
    )
    return period


def apply_usage(db, node_id, epoch, sample):
    device = db.execute(
        "SELECT * FROM devices WHERE id=?", (sample.user_id,)
    ).fetchone()
    if not device:
        user = db.execute(
            "SELECT * FROM users WHERE id=?", (sample.user_id,)
        ).fetchone()
        if not user:
            return
        ensure_identity(db, user)
        device = db.execute(
            "SELECT * FROM devices WHERE id=?", (sample.user_id,)
        ).fetchone()
    uid = device["user_id"]
    db.lock("user:" + uid)
    state = db.execute("SELECT * FROM user_state WHERE user_id=?", (uid,)).fetchone()
    period = sample.period_id or state["period_id"]
    record = db.execute(
        "SELECT id FROM user_periods WHERE id=? AND user_id=?", (period, uid)
    ).fetchone()
    if not record:
        raise ValueError("Unknown usage period")
    if device["legacy"] and not sample.period_id:
        # Preserve v0.2 baselines for old agents; late-report boundary remains
        # documented until the old agent is upgraded to period-aware reports.
        old = db.execute(
            "SELECT up,down FROM counters WHERE node_id=? AND epoch=? AND user_id=?",
            (node_id, epoch, uid),
        ).fetchone()
        up, down = (
            max(sample.up, old["up"] if old else 0),
            max(sample.down, old["down"] if old else 0),
        )
        db.execute(
            "INSERT INTO counters VALUES(?,?,?,?,?) ON CONFLICT(node_id,epoch,user_id) DO UPDATE SET up=excluded.up,down=excluded.down",
            (node_id, epoch, uid, up, down),
        )
    else:
        old = db.execute(
            "SELECT up,down FROM device_counters WHERE node_id=? AND epoch=? AND device_id=? AND period_id=?",
            (node_id, epoch, device["id"], period),
        ).fetchone()
        up, down = (
            max(sample.up, old["up"] if old else 0),
            max(sample.down, old["down"] if old else 0),
        )
        db.execute(
            "INSERT INTO device_counters VALUES(?,?,?,?,?,?) ON CONFLICT(node_id,epoch,device_id,period_id) DO UPDATE SET up=excluded.up,down=excluded.down",
            (node_id, epoch, device["id"], period, up, down),
        )
    du, dd = up - (old["up"] if old else 0), down - (old["down"] if old else 0)
    db.execute(
        "UPDATE user_periods SET uploaded=uploaded+?,downloaded=downloaded+? WHERE id=?",
        (du, dd, period),
    )
    if period == state["period_id"]:
        db.execute(
            "UPDATE users SET used=used+?,uploaded=uploaded+?,downloaded=downloaded+? WHERE id=?",
            (du + dd, du, dd, uid),
        )
    if du + dd > 0 and not state["first_used"]:
        now = int(time.time())
        db.execute("UPDATE user_state SET first_used=? WHERE user_id=?", (now, uid))
        if state["validity_seconds"]:
            db.execute(
                "UPDATE users SET expires=? WHERE id=? AND expires IS NULL",
                (now + state["validity_seconds"], uid),
            )
