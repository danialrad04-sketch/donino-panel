"""Enrollment and rotation for node-specific mutual-TLS identities."""

import secrets
import json
import os
import time
import uuid

from cryptography.hazmat.primitives import hashes
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .db import audit, database, digest
from .deps import node_auth, one, owner
from .node_identity import issue_certificate, public_material
from .security import clear_failures, guard, record_failure


class EnrollmentInput(BaseModel):
    node_id: str = Field(min_length=1, max_length=64)
    token: str = Field(min_length=32, max_length=128)
    csr: str = Field(min_length=100, max_length=12000)


class RenewalInput(BaseModel):
    csr: str = Field(min_length=100, max_length=12000)


def register_certificate(db, node, csr, *, renewal=False):
    try:
        cert, pem = issue_certificate(node["id"], csr)
    except ValueError as exc:
        raise HTTPException(422, "Invalid node certificate request") from exc
    now = int(time.time())
    if renewal:
        # At most one previous identity can overlap, with a bounded handoff window.
        db.execute(
            "UPDATE node_certificates SET revoked=1 WHERE node_id=? AND grace_until IS NOT NULL",
            (node["id"],),
        )
        db.execute(
            "UPDATE node_certificates SET grace_until=? WHERE node_id=? AND revoked=0",
            (now + 600, node["id"]),
        )
    else:
        db.execute(
            "UPDATE node_certificates SET revoked=1 WHERE node_id=?", (node["id"],)
        )
    db.execute(
        "INSERT INTO node_certificates(fingerprint,node_id,serial,expires,created) VALUES(?,?,?,?,?)",
        (
            cert.fingerprint(hashes.SHA256()).hex(),
            node["id"],
            str(cert.serial_number),
            int(cert.not_valid_after_utc.timestamp()),
            now,
        ),
    )
    db.execute("UPDATE nodes SET auth_mode='mtls' WHERE id=?", (node["id"],))
    return {
        "node_id": node["id"],
        "certificate": pem,
        "expires": int(cert.not_valid_after_utc.timestamp()),
        **public_material(),
    }


def mount_node_api(app):
    @app.post("/api/nodes/{nid}/enrollment", status_code=201)
    def enrollment_token(nid: str, account=Depends(owner)):
        if len(os.environ.get("DONINO_PROXY_KEY", "")) < 32:
            raise HTTPException(
                503,
                "ثبت امن به تنظیم پراکسی معتبر نیاز دارد؛ کنترل‌پنل را با نصب‌کنندهٔ جدید ارتقا دهید",
            )
        token, now = secrets.token_urlsafe(40), int(time.time())
        with database() as db:
            one(db, "nodes", nid)
            db.execute("DELETE FROM node_enrollments WHERE node_id=?", (nid,))
            db.execute(
                "INSERT INTO node_enrollments(id,node_id,token_hash,expires,created) VALUES(?,?,?,?,?)",
                (str(uuid.uuid4()), nid, digest(token), now + 600, now),
            )
            audit(db, account["username"], "node.enrollment-token", nid)
        return {"node_id": nid, "token": token, "expires": now + 600}

    @app.get("/api/nodes/{nid}/certificates")
    def certificates(nid: str, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", nid)
            return [
                dict(row)
                for row in db.execute(
                    "SELECT fingerprint,serial,expires,grace_until,revoked,created FROM node_certificates WHERE node_id=? ORDER BY created DESC",
                    (nid,),
                )
            ]

    @app.post("/api/nodes/{nid}/revoke-certificates")
    def revoke_certificates(nid: str, account=Depends(owner)):
        with database() as db:
            one(db, "nodes", nid)
            db.execute("UPDATE node_certificates SET revoked=1 WHERE node_id=?", (nid,))
            db.execute("DELETE FROM node_enrollments WHERE node_id=?", (nid,))
            audit(db, account["username"], "node.certificates-revoke", nid)
        return {"ok": True}

    @app.post("/api/agent/enroll", status_code=201)
    def enroll(body: EnrollmentInput, request: Request):
        now = int(time.time())
        address = "enroll:" + (request.client.host if request.client else "unknown")
        with database() as db:
            guard(db, address, now)
            row = db.execute(
                "SELECT * FROM node_enrollments WHERE node_id=? AND token_hash=? AND expires>?",
                (body.node_id, digest(body.token), now),
            ).fetchone()
            node = db.execute(
                "SELECT * FROM nodes WHERE id=? AND enabled=1", (body.node_id,)
            ).fetchone()
            if not row or not node:
                record_failure(db, address, now)
                return JSONResponse(
                    {"detail": "Invalid, expired or consumed enrollment token"},
                    status_code=401,
                )
            if row["used"] is not None:
                if row["request_hash"] == digest(body.csr) and row["response"]:
                    response = json.loads(row["response"])
                    from cryptography import x509

                    certificate = x509.load_pem_x509_certificate(
                        response["certificate"].encode()
                    )
                    active = db.execute(
                        "SELECT 1 FROM node_certificates WHERE fingerprint=? AND revoked=0 AND expires>?",
                        (certificate.fingerprint(hashes.SHA256()).hex(), now),
                    ).fetchone()
                    if active:
                        return response
                record_failure(db, address, now)
                return JSONResponse(
                    {"detail": "Enrollment token was already consumed"}, status_code=401
                )
            result = register_certificate(db, node, body.csr)
            db.execute(
                "UPDATE node_enrollments SET used=?,request_hash=?,response=? WHERE id=?",
                (now, digest(body.csr), json.dumps(result), row["id"]),
            )
            clear_failures(db, address)
            audit(db, "node-enrollment", "node.certificate-issue", node["id"])
        return result

    @app.post("/api/agent/renew-certificate")
    def renew(body: RenewalInput, node=Depends(node_auth)):
        if node["auth_mode"] != "mtls":
            raise HTTPException(403, "Certificate authentication required for renewal")
        with database() as db:
            result = register_certificate(db, node, body.csr, renewal=True)
            audit(db, "node:" + node["id"], "node.certificate-renew", node["id"])
        return result
