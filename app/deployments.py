"""Persist desired config jobs and acknowledge only the matching node/revision.

This is a typed apply-config queue. It never accepts remote shell commands.
Payloads contain credentials and stay in the private database, outside list APIs.
"""

import json
import time
import uuid

from .core import revision


def desired_job(db, node_id, config, periods):
    payload = {"config": config, "periods": periods}
    checksum = revision(payload)
    head = db.execute("SELECT desired_job FROM nodes WHERE id=?", (node_id,)).fetchone()
    current = (
        db.execute(
            "SELECT id,revision FROM deployments WHERE id=? AND node_id=?",
            (head[0], node_id),
        ).fetchone()
        if head and head[0]
        else None
    )
    if current and current["revision"] == checksum:
        return current["id"], checksum
    now, job_id = int(time.time()), str(uuid.uuid4())
    db.execute(
        "UPDATE deployments SET state='superseded',updated=? WHERE node_id=? AND state IN ('pending','failed')",
        (now, node_id),
    )
    db.execute(
        "INSERT INTO deployments(id,node_id,revision,engine,state,payload,created,updated) VALUES(?,?,?,'xray','pending',?,?,?)",
        (
            job_id,
            node_id,
            checksum,
            json.dumps(payload, separators=(",", ":")),
            now,
            now,
        ),
    )
    db.execute("UPDATE nodes SET desired_job=?,config_sequence=config_sequence+1 WHERE id=?", (job_id, node_id))
    return job_id, checksum


def acknowledge(db, node_id, body, now):
    if not body.job_id:
        return  # Legacy agents do not acknowledge typed jobs.
    job = db.execute(
        "SELECT * FROM deployments WHERE id=? AND node_id=?", (body.job_id, node_id)
    ).fetchone()
    if not job or job["state"] == "superseded":
        return
    if body.error and body.rejected_revision == job["revision"]:
        state = "failed"
    elif (
        not body.error
        and body.applied_revision == job["revision"]
        and body.core_running is True
    ):
        state = "applied"
    else:
        return
    db.execute(
        "UPDATE deployments SET state=?,error=?,updated=? WHERE id=?",
        (state, body.error, now, job["id"]),
    )
