"""User network assignments and immutable usage-period history."""

from fastapi import Depends
from pydantic import BaseModel, Field

from .accounting import ensure_period
from .db import audit, database
from .deps import admin, one, writer, owner
from .engines import XRAY


class AssignmentsInput(BaseModel):
    mode: str = Field(pattern="^(all|selected)$")
    node_ids: list[str] = Field(default_factory=list, max_length=1000)


def mount_network_api(app):
    @app.get("/api/engines")
    def engines(account=Depends(admin)):
        return [XRAY.capabilities()]

    @app.get("/api/deployments")
    def deployments(account=Depends(owner)):
        with database() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id,node_id,revision,engine,state,created,updated,error FROM deployments ORDER BY created DESC,id DESC LIMIT 100"
                )
            ]

    @app.get("/api/users/{uid}/periods")
    def periods(uid: str, account=Depends(admin)):
        with database() as db:
            user = one(db, "users", uid)
            ensure_period(db, user)
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM usage_periods WHERE user_id=? ORDER BY period_no DESC LIMIT 120",
                    (uid,),
                )
            ]

    @app.get("/api/users/{uid}/nodes")
    def assignments(uid: str, account=Depends(admin)):
        with database() as db:
            user = one(db, "users", uid)
            return {
                "mode": user["node_mode"],
                "node_ids": [
                    row[0]
                    for row in db.execute(
                        "SELECT node_id FROM user_nodes WHERE user_id=? ORDER BY node_id",
                        (uid,),
                    )
                ],
            }

    @app.put("/api/users/{uid}/nodes")
    def update_assignments(uid: str, body: AssignmentsInput, account=Depends(writer)):
        with database() as db:
            one(db, "users", uid)
            for node_id in set(body.node_ids):
                one(db, "nodes", node_id)
            db.execute("DELETE FROM user_nodes WHERE user_id=?", (uid,))
            db.execute("UPDATE users SET node_mode=? WHERE id=?", (body.mode, uid))
            if body.mode == "selected":
                for node_id in sorted(set(body.node_ids)):
                    db.execute(
                        "INSERT INTO user_nodes(user_id,node_id) VALUES(?,?)",
                        (uid, node_id),
                    )
            audit(db, account["username"], "user.assign-nodes", uid)
        return {
            "mode": body.mode,
            "node_ids": sorted(set(body.node_ids)) if body.mode == "selected" else [],
        }
