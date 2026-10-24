"""Cryptographic primitives.

We do NOT invent any crypto here. We only combine two well-reviewed building
blocks:

* Argon2id (memory-hard KDF) turns the master password into a key.
* AES-256-GCM (authenticated encryption) protects data and detects tampering.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32      # 256-bit keys
SALT_LEN = 16
NONCE_LEN = 12    # recommended size for GCM


class DecryptionError(Exception):
    """Wrong key, wrong context, or data was modified."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters (stored in the vault so they can be upgraded).

    Defaults follow OWASP guidance: 64 MiB of memory, 3 passes, 4 lanes.
    """
    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024
    parallelism: int = 4

    def __post_init__(self) -> None:
        # The header (and remote prelogin response) is untrusted input. Bound
        # Argon2 work before it can trigger multi-gigabyte allocations.
        if not 1 <= self.time_cost <= 10:
            raise ValueError("Argon2id time_cost must be between 1 and 10")
        if not 8 <= self.memory_cost_kib <= 512 * 1024:
            raise ValueError("Argon2id memory_cost_kib must be between 8 and 524288")
        if not 1 <= self.parallelism <= 16:
            raise ValueError("Argon2id parallelism must be between 1 and 16")
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValueError("Argon2id memory_cost_kib must be at least 8 times parallelism")


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Master password + salt -> 32-byte key using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Output = nonce || ciphertext+tag.

    `aad` (associated data) is authenticated but not encrypted. We bind each
    blob to its context so it can't be silently moved elsewhere.
    """
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise DecryptionError("ciphertext too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc
