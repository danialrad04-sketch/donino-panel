"""Owner-only staged import metadata; private source archives are not exposed."""

import json

from fastapi import Depends

from .db import database
from .deps import one, owner


def mount_doctor_api(app):
    @app.get("/api/imports/doctor")
    def imports(account=Depends(owner)):
        with database() as db:
            values = [
                dict(r)
                for r in db.execute(
                    "SELECT id,source_instance,fingerprint,source_revision,state,summary,created,reverted FROM doctor_imports ORDER BY created DESC LIMIT 100"
                )
            ]
        for value in values:
            value["summary"] = json.loads(value["summary"])
        return values

    @app.get("/api/imports/doctor/{import_id}/users")
    def users(import_id: str, account=Depends(owner)):
        with database() as db:
            one(db, "doctor_imports", import_id)
            return [
                dict(r)
                for r in db.execute(
                    "SELECT d.external_id,d.user_id,u.name,d.quota_bytes,d.used_bytes,d.source_status,d.period_mode,d.reset_at,d.expires FROM doctor_import_users d JOIN users u ON u.id=d.user_id WHERE d.import_id=? ORDER BY d.external_id LIMIT 1000",
                    (import_id,),
                )
            ]

    @app.get("/api/imports/doctor/{import_id}/templates")
    def templates(import_id: str, account=Depends(owner)):
        with database() as db:
            one(db, "doctor_imports", import_id)
            values = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM doctor_import_templates WHERE import_id=? ORDER BY external_id LIMIT 1000",
                    (import_id,),
                )
            ]
        for value in values:
            for field in ("selections", "exclusions", "custom_domains"):
                value[field] = json.loads(value[field])
        return values
