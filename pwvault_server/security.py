"""Server-side security helpers: hashing, tokens, TOTP, secret storage."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from pwvault import crypto
from .config import Settings

_ph = PasswordHasher()           # Argon2id, library defaults
ALGORITHM = "HS256"
TOTP_PERIOD = 30


# Wrapped so tests can control time.
def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def current_time() -> float:
    return time.time()


# ------------------------------------------------------------ auth key hash
def hash_auth_key(auth_key_b64: str) -> str:
    """Second hash: even a stolen database cannot be used to log in, because
    the stored value is a slow hash of what the client sends."""
    return _ph.hash(auth_key_b64)


def verify_auth_key(stored_hash: str, auth_key_b64: str) -> bool:
    try:
        return _ph.verify(stored_hash, auth_key_b64)
    except (VerificationError, InvalidHashError):
        return False


# Verified for unknown e-mails so response time doesn't reveal who exists.
DUMMY_HASH = _ph.hash("pwvault-dummy-value")


def fake_salt(settings: Settings, email: str) -> bytes:
    """Stable pseudo-random salt for unknown users (prevents enumeration via
    /prelogin: a real and a fake account look identical)."""
    return hmac.new(settings.server_key, b"fake-salt:" + email.encode(),
                    hashlib.sha256).digest()[:16]


# -------------------------------------------------------------------- JWT
def create_token(settings: Settings, user_id: str, token_version: int) -> str:
    now = utcnow().replace(tzinfo=timezone.utc)
    payload = {"sub": user_id, "tv": token_version, "iat": now,
               "exp": now + timedelta(minutes=settings.token_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(settings: Settings, token: str) -> dict:
    """Raises jwt.PyJWTError for any invalid/expired token. The algorithm is
    pinned, so 'alg: none' and algorithm-confusion tricks are rejected."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM],
                      options={"require": ["exp", "iat", "sub"]})


# ------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="pwvault")


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the accepted time-step, or None. Accepts +-1 step of clock drift
    and refuses any step <= last_step, so a code can never be replayed."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(current_time() // TOTP_PERIOD)
    accepted = None
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * TOTP_PERIOD), code):
            accepted = step
    return accepted


def encrypt_secret(settings: Settings, user_id: str, secret: str) -> bytes:
    return crypto.encrypt(settings.server_key, secret.encode(),
                          b"pwvault:totp:" + user_id.encode())


def decrypt_secret(settings: Settings, user_id: str, blob: bytes) -> str:
    return crypto.decrypt(settings.server_key, blob,
                          b"pwvault:totp:" + user_id.encode()).decode()


# ---------------------------------------------------------- recovery codes
def generate_recovery_codes(n: int = 8) -> list[str]:
    # 80 random bits per code (two groups of 5 bytes).
    return [f"{secrets.token_hex(5)}-{secrets.token_hex(5)}" for _ in range(n)]


def hash_recovery_code(code: str) -> str:
    # 80 bits of entropy per code, so a fast hash is acceptable here
    # (unlike passwords, brute-forcing 2^80 is infeasible even offline).
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()
