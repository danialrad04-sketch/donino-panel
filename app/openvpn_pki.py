"""Separate per-endpoint data-plane CA; never the node/control-plane CA."""

import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def pem_key(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def authority(endpoint_id):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Donino VPN CA " + endpoint_id)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return pem_key(key), cert.public_bytes(serialization.Encoding.PEM).decode()


def issue(ca_key, ca_cert, name, *, server=False):
    root = x509.load_pem_x509_certificate(ca_cert.encode())
    signer = serialization.load_pem_private_key(ca_key.encode(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if server
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
        .sign(signer, hashes.SHA256())
    )
    return (
        pem_key(key),
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        str(cert.serial_number),
    )


def tls_crypt_key():
    value = secrets.token_hex(256)
    return (
        "-----BEGIN OpenVPN Static key V1-----\n"
        + "\n".join(value[i : i + 32] for i in range(0, len(value), 32))
        + "\n-----END OpenVPN Static key V1-----\n"
    )


def fingerprint(cert):
    return (
        x509.load_pem_x509_certificate(cert.encode()).fingerprint(hashes.SHA256()).hex()
    )
