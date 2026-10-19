"""Shadowsocks AEAD credentials, scoped to protocol, inbound and method.

2022 multi-user AES needs a server key AND a separate identity key per device.
The server key alone must never become an unmetered single-user fallback.
"""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secrets import unseal

METHODS = (
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
)


def key_size(method):
    if method not in METHODS:
        raise ValueError("Unsupported Shadowsocks AEAD method")
    return 16 if method == "2022-blake3-aes-128-gcm" else 32


def device_key(secret, inbound_id, method):
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=key_size(method),
        salt=None,
        info=("donino/shadowsocks/device/v1/" + inbound_id + "/" + method).encode(),
    ).derive(secret.encode())
    return base64.b64encode(material).decode()


def client_password(secret, inbound_id, settings):
    method = settings["ss_method"]
    key = device_key(secret, inbound_id, method)
    if method.startswith("2022-"):
        return unseal(settings["ss_server_key"]) + ":" + key
    return key
