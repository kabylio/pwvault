import pytest

from pwvault import KdfParams

# Tiny Argon2 cost so the test-suite runs in milliseconds.
FAST_KDF = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)
MASTER = "correct horse battery staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.db"
