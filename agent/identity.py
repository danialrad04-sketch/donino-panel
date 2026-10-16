"""Atomic node identity handoff and pinned signed-config verification state."""

import json
import os
import re
import shutil
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.node_identity import decode, private_bytes
from ops.common import atomic_write


def validate_origin(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise ValueError(
            "Enrollment requires an HTTPS origin, without credentials or a path"
        )
    return value


def certificate_request(key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Donino enrollment")])
        )
        .sign(key, hashes.SHA256())
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, csr.public_bytes(serialization.Encoding.PEM).decode()


def save_identity(directory, panel, expected_node, result, private_key):
    directory = Path(directory)
    if (
        result["node_id"] != expected_node
        or len(decode(result["config_verify_key"])) != 32
    ):
        raise ValueError("Enrollment identity differs from the requested node")
    cert = x509.load_pem_x509_certificate(result["certificate"].encode())
    ca = x509.load_pem_x509_certificate(result["ca_certificate"].encode())
    cert.verify_directly_issued_by(ca)
    key = serialization.load_pem_private_key(private_key, password=None)
    if key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("Certificate and local private key differ")
    if (
        list(
            cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
        )
        != ["urn:donino:node:" + expected_node]
        or ExtendedKeyUsageOID.CLIENT_AUTH
        not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ):
        raise ValueError("Certificate has the wrong node identity or purpose")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity_name = "identity-" + cert.fingerprint(hashes.SHA256()).hex()[:16]
    temporary = Path(tempfile.mkdtemp(prefix=".enrollment-", dir=directory))
    try:
        for name, value in {
            "client.key": private_key,
            "client.crt": result["certificate"],
            "node-ca.crt": result["ca_certificate"],
        }.items():
            atomic_write(temporary / name, value)
        metadata = {
            "panel": panel,
            "node_id": expected_node,
            "directory": identity_name,
            "config_verify_key": result["config_verify_key"],
            "expires": int(cert.not_valid_after_utc.timestamp()),
        }
        atomic_write(temporary / "identity.json", json.dumps(metadata))
        destination = directory / identity_name
        if destination.exists():
            if destination.is_symlink() or any(
                private_bytes(destination / path.name) != path.read_bytes()
                for path in temporary.iterdir()
            ):
                raise ValueError(
                    "An existing identity directory has different material"
                )
        else:
            os.rename(temporary, destination)
        atomic_write(directory / "identity.json", json.dumps(metadata))
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return metadata


def load_identity(directory, panel):
    directory = Path(directory)
    pointer = directory / "identity.json"
    if not pointer.exists():
        return None
    value = json.loads(private_bytes(pointer))
    if value["panel"] != panel or not re.fullmatch(
        r"identity-[0-9a-f]{16}", value["directory"]
    ):
        raise ValueError(
            "Node identity belongs to another panel or has an invalid directory"
        )
    for name in ("client.key", "client.crt", "node-ca.crt"):
        private_bytes(directory / value["directory"] / name)
    return value


def panel_client(panel, *, directory=None, identity=None, token=None, ca_file=None):
    context = ssl.create_default_context(
        cafile=ca_file or os.environ.get("DONINO_PANEL_CA_FILE")
    )
    headers = {}
    if identity:
        root = Path(directory) / identity["directory"]
        context.load_cert_chain(root / "client.crt", root / "client.key")
    elif token:
        headers["Authorization"] = "Bearer " + token
    return httpx.Client(
        base_url=panel,
        verify=context,
        timeout=12,
        follow_redirects=False,
        headers=headers,
    )
