import pytest

from pwvault import crypto
from pwvault.crypto import DecryptionError
from .conftest import FAST_KDF


def test_roundtrip():
    key = crypto.random_bytes(32)
    assert crypto.decrypt(key, crypto.encrypt(key, b"secret")) == b"secret"


def test_nonce_is_random():
    key = crypto.random_bytes(32)
    assert crypto.encrypt(key, b"x") != crypto.encrypt(key, b"x")


def test_wrong_key_fails():
    blob = crypto.encrypt(crypto.random_bytes(32), b"secret")
    with pytest.raises(DecryptionError):
        crypto.decrypt(crypto.random_bytes(32), blob)


def test_tampering_detected():
    key = crypto.random_bytes(32)
    blob = bytearray(crypto.encrypt(key, b"secret"))
    blob[-1] ^= 1
    with pytest.raises(DecryptionError):
        crypto.decrypt(key, bytes(blob))


def test_aad_mismatch_fails():
    key = crypto.random_bytes(32)
    blob = crypto.encrypt(key, b"secret", aad=b"a")
    with pytest.raises(DecryptionError):
        crypto.decrypt(key, blob, aad=b"b")


def test_kdf_deterministic_and_salt_sensitive():
    salt = b"s" * 16
    k1 = crypto.derive_key("pw", salt, FAST_KDF)
    assert k1 == crypto.derive_key("pw", salt, FAST_KDF)
    assert k1 != crypto.derive_key("pw", b"t" * 16, FAST_KDF)
    assert k1 != crypto.derive_key("pW", salt, FAST_KDF)
    assert len(k1) == 32


@pytest.mark.parametrize("kwargs", [
    {"time_cost": 0},
    {"time_cost": 11},
    {"memory_cost_kib": 7},
    {"memory_cost_kib": 524_289},
    {"parallelism": 0},
    {"parallelism": 17},
    {"memory_cost_kib": 8, "parallelism": 2},
])
def test_unsafe_kdf_limits_are_rejected(kwargs):
    with pytest.raises(ValueError):
        crypto.KdfParams(**kwargs)
