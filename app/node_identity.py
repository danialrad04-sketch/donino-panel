"""Private node CA and signed desired-state envelopes using standard cryptography."""

import base64
import fcntl
import hmac
import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException

from .db import database, db_path
from ops.common import atomic_write

CONFIG_CONTEXT = b"donino.desired.v1\0"
CERT_DAYS = 14
PKI_FILES = ("node-ca.key", "node-ca.crt", "config-signing.key")


def pki_directory():
    return Path(os.environ.get("DONINO_PKI_DIR", str(db_path().parent / "pki")))


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        mode = os.fstat(file.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise RuntimeError("PKI material must be a private regular file (0600)")
        return file.read()


def ensure_material():
    directory = pki_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(
        directory / "material.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ca_key_path, ca_cert_path = directory / "node-ca.key", directory / "node-ca.crt"
        if ca_key_path.exists() != ca_cert_path.exists():
            raise RuntimeError(
                "Incomplete node CA; restore the matching private key and certificate"
            )
        if not ca_key_path.exists():
            if (directory / "initialized").exists():
                raise RuntimeError(
                    "Node CA is missing; restore PKI instead of replacing the trust root"
                )
            key = ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(timezone.utc)
            name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "Donino node CA")]
            )
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0), critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            atomic_write(
                ca_key_path,
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            atomic_write(
                ca_cert_path, certificate.public_bytes(serialization.Encoding.PEM)
            )
        ca_key = serialization.load_pem_private_key(
            private_bytes(ca_key_path), password=None
        )
        ca = x509.load_pem_x509_certificate(private_bytes(ca_cert_path))
        if ca_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != ca.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise RuntimeError("Node CA certificate and private key differ")
        signing_path = directory / "config-signing.key"
        if not signing_path.exists():
            if (directory / "initialized").exists():
                raise RuntimeError(
                    "Config signing key is missing; restore the pinned key"
                )
            atomic_write(
                signing_path, ed25519.Ed25519PrivateKey.generate().private_bytes_raw()
            )
        signing = ed25519.Ed25519PrivateKey.from_private_bytes(
            private_bytes(signing_path)
        )
        if not (directory / "initialized").exists():
            atomic_write(directory / "initialized", "donino-node-pki-v1\n")
    return ca_key, ca, signing


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode(value):
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def public_material():
    _, ca, signing = ensure_material()
    return {
        "ca_certificate": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "config_verify_key": encoded(signing.public_key().public_bytes_raw()),
    }


def sign_desired(payload, *, sequence, now=None):
    now = int(time.time()) if now is None else now
    _, _, signing = ensure_material()
    reserved = {
        "signature",
        "issued_at",
        "valid_until",
        "sequence",
        "signature_version",
    }
    envelope = {
        **{key: value for key, value in payload.items() if key not in reserved},
        "issued_at": now,
        "valid_until": now + 60,
        "sequence": sequence,
        "signature_version": 1,
    }
    envelope["signature"] = encoded(signing.sign(CONFIG_CONTEXT + canonical(envelope)))
    return envelope


def verify_desired(envelope, verify_key, node_id, *, sequence=0, now=None):
    now = int(time.time()) if now is None else now
    body = {key: value for key, value in envelope.items() if key != "signature"}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(decode(verify_key)).verify(
            decode(envelope["signature"]), CONFIG_CONTEXT + canonical(body)
        )
        if body["signature_version"] != 1 or body["node_id"] != node_id:
            raise ValueError("Wrong node or signature format")
        if type(body["sequence"]) is not int or body["sequence"] < sequence:
            raise ValueError("Config sequence went backwards")
        if not all(type(body[name]) is int for name in ("issued_at", "valid_until")):
            raise ValueError("Invalid config time")
        if (
            body["issued_at"] > now + 5
            or body["issued_at"] < now - 65
            or body["valid_until"] <= now
            or not 0 < body["valid_until"] - body["issued_at"] <= 60
        ):
            raise ValueError("Expired or future config")
    except Exception as exc:
        raise ValueError(
            "Desired config signature, identity, sequence or validity check failed"
        ) from exc
    return body


def issue_certificate(node_id, csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    key = csr.public_key()
    if not csr.is_signature_valid or not (
        isinstance(key, ec.EllipticCurvePublicKey)
        and isinstance(key.curve, ec.SECP256R1)
        or isinstance(key, rsa.RSAPublicKey)
        and 2048 <= key.key_size <= 4096
    ):
        raise ValueError("CSR needs a valid signature and P-256 or RSA 2048–4096 key")
    ca_key, ca, _ = ensure_material()
    now = datetime.now(timezone.utc)
    if ca.not_valid_after_utc < now + timedelta(days=CERT_DAYS):
        raise ValueError("Node CA is too close to expiry")
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
        .issuer_name(ca.subject)
        .public_key(key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(days=CERT_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("urn:donino:node:" + node_id)]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, cert.public_bytes(serialization.Encoding.PEM).decode()


def certificate_auth(request):
    expected = os.environ.get("DONINO_PROXY_KEY", "")
    if (
        len(expected) < 32
        or not hmac.compare_digest(
            request.headers.get("x-donino-proxy-key", ""), expected
        )
        or request.headers.get("x-donino-client-verify") != "SUCCESS"
    ):
        raise HTTPException(401, "Verified node certificate required")
    try:
        certificate = x509.load_pem_x509_certificate(
            unquote(request.headers["x-donino-client-cert"]).encode()
        )
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    except (ValueError, KeyError) as exc:
        raise HTTPException(401, "Invalid node certificate") from exc
    now = int(time.time())
    with database() as db:
        node = db.execute(
            """SELECT n.* FROM nodes n JOIN node_certificates c ON c.node_id=n.id
            WHERE c.fingerprint=? AND c.revoked=0 AND c.expires>? AND (c.grace_until IS NULL OR c.grace_until>?)
            AND n.enabled=1 AND n.auth_mode='mtls'""",
            (fingerprint, now, now),
        ).fetchone()
    if not node:
        raise HTTPException(401, "Node certificate was revoked, expired or disabled")
    return dict(node)
