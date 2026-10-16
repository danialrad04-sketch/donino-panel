"""Period history and cumulative usage, serialized by the database writer lock."""

from fastapi import HTTPException

from .db import upsert


def ensure_period(db, user):
    db.execute(
        """INSERT INTO usage_periods(user_id,period_no,started,uploaded,downloaded,legacy_used)
        VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,period_no) DO NOTHING""",
        (
            user["id"],
            user["period_no"],
            user["period_start"] if user["period"] == "monthly" else user["created"],
            user["uploaded"],
            user["downloaded"],
            user["legacy_used"],
        ),
    )


def next_period(db, user, now, *, start=None):
    ensure_period(db, user)
    db.execute(
        "UPDATE usage_periods SET ended=? WHERE user_id=? AND period_no=?",
        (now, user["id"], user["period_no"]),
    )
    db.execute(
        """INSERT INTO usage_periods(user_id,period_no,started) VALUES(?,?,?)""",
        (user["id"], user["period_no"] + 1, start),
    )
    db.execute(
        """UPDATE users SET used=0,uploaded=0,downloaded=0,legacy_used=0,
        period_no=period_no+1,period_start=? WHERE id=?""",
        (start, user["id"]),
    )
    db.execute(
        "UPDATE devices SET uploaded=0,downloaded=0 WHERE user_id=?", (user["id"],)
    )


def apply_sample(db, node_id, epoch, sample, now):
    device = db.execute(
        "SELECT id,user_id FROM devices WHERE id=?", (sample.user_id,)
    ).fetchone()
    if not device:
        return
    user = db.execute("SELECT * FROM users WHERE id=?", (device["user_id"],)).fetchone()
    ensure_period(db, user)
    old = db.execute(
        "SELECT up,down,period_no FROM counters WHERE node_id=? AND epoch=? AND device_id=?",
        (node_id, epoch, device["id"]),
    ).fetchone()
    # Once an explicit generation owns a process/device counter it cannot change.
    generation = sample.period_no
    if old and old["period_no"] is not None:
        if generation is not None and generation != old["period_no"]:
            raise HTTPException(
                409, "A usage epoch cannot change its period generation"
            )
        generation = old["period_no"]
    period_no = user["period_no"] if generation is None else generation
    if not db.execute(
        "SELECT 1 FROM usage_periods WHERE user_id=? AND period_no=?",
        (user["id"], period_no),
    ).fetchone():
        raise HTTPException(409, "Unknown usage period; sample was not acknowledged")
    up, down = (
        max(sample.up, old["up"] if old else 0),
        max(sample.down, old["down"] if old else 0),
    )
    delta_up, delta_down = (
        up - (old["up"] if old else 0),
        down - (old["down"] if old else 0),
    )
    db.execute(
        "UPDATE usage_periods SET uploaded=uploaded+?,downloaded=downloaded+? WHERE user_id=? AND period_no=?",
        (delta_up, delta_down, user["id"], period_no),
    )
    if period_no == user["period_no"]:
        db.execute(
            "UPDATE users SET used=used+?,uploaded=uploaded+?,downloaded=downloaded+? WHERE id=?",
            (delta_up + delta_down, delta_up, delta_down, user["id"]),
        )
        db.execute(
            "UPDATE devices SET uploaded=uploaded+?,downloaded=downloaded+? WHERE id=?",
            (delta_up, delta_down, device["id"]),
        )
        if delta_up + delta_down > 0:
            db.execute(
                "UPDATE usage_periods SET started=COALESCE(started,?) WHERE user_id=? AND period_no=?",
                (now, user["id"], period_no),
            )
            db.execute(
                "UPDATE users SET period_start=COALESCE(period_start,?) WHERE id=? AND period='monthly'",
                (now, user["id"]),
            )
    upsert(
        db,
        "counters",
        ["node_id", "epoch", "device_id", "up", "down", "period_no"],
        [node_id, epoch, device["id"], up, down, generation],
        ["node_id", "epoch", "device_id"],
    )
