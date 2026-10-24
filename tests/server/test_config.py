import pytest
from pydantic import ValidationError

from pwvault_server import Settings
from pwvault_server.schemas import Kdf


def test_short_jwt_secret_refused():
    with pytest.raises(ValueError):
        Settings(jwt_secret="short", server_key=bytes(32))


def test_bad_server_key_length_refused():
    with pytest.raises(ValueError):
        Settings(jwt_secret="x" * 40, server_key=b"too short")


@pytest.mark.parametrize("kwargs", [
    {"token_minutes": 0},
    {"max_failed_attempts": 0},
    {"lockout_minutes": 0},
    {"min_memory_kib": 4},
    {"min_memory_kib": 4_194_305},
    {"min_memory_kib": 8, "min_parallelism": 2},
])
def test_invalid_security_limits_refused(kwargs):
    with pytest.raises(ValueError):
        Settings(jwt_secret="x" * 40, server_key=bytes(32), **kwargs)


@pytest.mark.parametrize("params", [
    {"time_cost": 11, "memory_cost_kib": 19456, "parallelism": 1},
    {"time_cost": 2, "memory_cost_kib": 524289, "parallelism": 1},
    {"time_cost": 2, "memory_cost_kib": 19456, "parallelism": 17},
    {"time_cost": 1, "memory_cost_kib": 8, "parallelism": 2},
])
def test_unsafe_client_kdf_params_refused(params):
    with pytest.raises(ValidationError):
        Kdf(**params)


def test_missing_env_gives_helpful_error(monkeypatch):
    monkeypatch.delenv("PWVAULT_JWT_SECRET", raising=False)
    monkeypatch.delenv("PWVAULT_SERVER_KEY", raising=False)
    with pytest.raises(RuntimeError, match="gen_secrets"):
        Settings.from_env()
