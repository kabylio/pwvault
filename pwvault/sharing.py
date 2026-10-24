"""Public-key sharing primitives (X25519 + HKDF + AES-256-GCM, ECIES-style).

To give someone a secret, we generate a throw-away X25519 key, do a
Diffie-Hellman with the recipient's public key, derive an AES key from the
result, and encrypt. Only the holder of the recipient's PRIVATE key can repeat
the DH and decrypt. Every blob is bound (as AAD) to the vault, the member and
the key version, so it cannot be replayed somewhere else.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption,
                                                          PrivateFormat, PublicFormat)

from . import crypto
from .crypto import DecryptionError

PRIV_AAD = b"pwvault:private-key:v1"
_PUB_LEN = 32


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private, public), both 32 raw bytes."""
    priv = X25519PrivateKey.generate()
    return (priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_from_private(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def fingerprint(pub: bytes) -> str:
    """Human-comparable key fingerprint. Read it to your colleague by phone or
    in person before sharing: this is what defeats a key-swapping server."""
    h = hashlib.sha256(pub).hexdigest()[:32].upper()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def _key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=b"pwvault:share:v1").derive(shared)


def wrap_for(recipient_pub: bytes, secret: bytes, aad: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    return eph_pub + crypto.encrypt(_key(shared, eph_pub, recipient_pub), secret, aad)


def unwrap(private_key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < _PUB_LEN + 28:
        raise DecryptionError("sealed blob too short")
    eph_pub = blob[:_PUB_LEN]
    try:
        shared = X25519PrivateKey.from_private_bytes(private_key).exchange(
            X25519PublicKey.from_public_bytes(eph_pub))
    except ValueError as exc:                   # e.g. low-order point
        raise DecryptionError("invalid ephemeral key") from exc
    return crypto.decrypt(_key(shared, eph_pub, public_from_private(private_key)),
                          blob[_PUB_LEN:], aad)


# ---- context binding (AAD) --------------------------------------------------
def key_aad(vault_id: str, user_id: str, key_version: int) -> bytes:
    return f"pwvault:vault-key:v1:{vault_id}:{user_id}:{key_version}".encode()


def entry_aad(vault_id: str, entry_id: str, key_version: int) -> bytes:
    return f"pwvault:shared-entry:v1:{vault_id}:{entry_id}:{key_version}".encode()


def name_aad(vault_id: str, key_version: int) -> bytes:
    return f"pwvault:vault-name:v1:{vault_id}:{key_version}".encode()
