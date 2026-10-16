"""Second-factor, API token and throttling primitives (standard library only)."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from fastapi import HTTPException

from .db import digest, upsert
from .secrets import PREFIX, unseal

TOTP_PERIOD = 30
RECOVERY_CODE_COUNT = 10
TOKEN_PREFIX = "dnk_"
MAX_TOKENS_PER_ADMIN = 20
MAX_TOKEN_DAYS = 365
LOCK_ATTEMPTS = 10
LOCK_SECONDS = 900
PASSWORD_MIN, PASSWORD_MAX = 12, 256
SCOPES = ("read", "users", "full")


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def totp_verify(secret, code, last_step=0, now=None, window=1, digits=6):
    """Return the matched time step, or None.

    A step at or below `last_step` is refused so a captured code cannot be
    replayed inside its validity window (RFC 6238 section 5.2).
    """
    if secret.startswith(PREFIX):
        secret = unseal(secret)
    code = re.sub(r"\s+", "", str(code))
    if not re.fullmatch(r"[0-9]{%d}" % digits, code):
        return None
    current = int((time.time() if now is None else now) // TOTP_PERIOD)
    matched = None
    for step in range(current - window, current + window + 1):
        # Compare every candidate so timing does not reveal which step matched.
        if hmac.compare_digest(hotp(secret, step, digits), code) and step > last_step:
            matched = step
    return matched


def otpauth_uri(secret, username, issuer="Donino"):
    label = quote(f"{issuer}:{username}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": 6,
            "period": TOTP_PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def normalize_recovery(code):
    return re.sub(r"[\s-]+", "", str(code)).lower()


def new_recovery_codes():
    codes = [
        (lambda raw: raw[:5] + "-" + raw[5:])(secrets.token_hex(5))
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    return codes, [digest(normalize_recovery(c)) for c in codes]


def check_second_factor(db, mfa, code):
    """Verify a TOTP or one-time recovery code and persist replay protection."""
    step = totp_verify(mfa["secret"], code, mfa["last_step"])
    if step is not None:
        db.execute(
            "UPDATE admin_mfa SET last_step=? WHERE username=?",
            (step, mfa["username"]),
        )
        return True
    hashes = json.loads(mfa["recovery"])
    candidate = digest(normalize_recovery(code))
    for stored in hashes:
        if hmac.compare_digest(stored, candidate):
            hashes.remove(stored)
            db.execute(
                "UPDATE admin_mfa SET recovery=? WHERE username=?",
                (json.dumps(hashes), mfa["username"]),
            )
            return True
    return False


def new_api_token():
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def is_api_token(value):
    return isinstance(value, str) and value.startswith(TOKEN_PREFIX)


def guard(db, key, now=None):
    """Raise 429 while `key` is locked out. Failures are recorded separately."""
    now = int(time.time()) if now is None else now
    row = db.execute("SELECT * FROM login_attempts WHERE address=?", (key,)).fetchone()
    if row and row["until"] > now and row["attempts"] >= LOCK_ATTEMPTS:
        raise HTTPException(429, "تلاش‌های زیاد؛ ۱۵ دقیقه دیگر دوباره امتحان کنید")
    return row


def record_failure(db, key, now=None):
    now = int(time.time()) if now is None else now
    row = db.execute("SELECT * FROM login_attempts WHERE address=?", (key,)).fetchone()
    count = row["attempts"] + 1 if row and row["until"] > now else 1
    upsert(
        db,
        "login_attempts",
        ["address", "attempts", "until"],
        [key, count, now + LOCK_SECONDS],
        ["address"],
    )


def clear_failures(db, key):
    db.execute("DELETE FROM login_attempts WHERE address=?", (key,))


def revoke_credentials(db, username, keep_session=None, tokens=True):
    """Invalidate sessions (optionally keeping one) and API tokens of an admin."""
    if keep_session:
        db.execute(
            "DELETE FROM sessions WHERE username=? AND token<>?",
            (username, keep_session),
        )
    else:
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
    if tokens:
        db.execute("DELETE FROM api_tokens WHERE username=?", (username,))
