import pytest
from fastapi.testclient import TestClient

from pwvault import KdfParams
from pwvault.remote import RemoteVault
from pwvault_server import Settings, create_app

# Smallest KDF the server accepts (keeps tests quick).
FAST = KdfParams(time_cost=2, memory_cost_kib=19456, parallelism=1)
MASTER = "correct horse battery staple"
EMAIL = "alice@bank.dz"


@pytest.fixture
def settings(tmp_path):
    return Settings(jwt_secret="j" * 48, server_key=bytes(range(32)),
                    database_url=f"sqlite:///{tmp_path / 'server.db'}",
                    admin_emails=("admin@bank.dz",))


@pytest.fixture
def http(settings):
    with TestClient(create_app(settings)) as client:
        yield client


def make_user(http, email=EMAIL, password=MASTER) -> RemoteVault:
    RemoteVault.register(http, email, password, kdf=FAST)
    return RemoteVault.login(http, email, password)


@pytest.fixture
def alice(http):
    return make_user(http)


@pytest.fixture
def bob(http):
    return make_user(http, "bob@bank.dz", "another long master password")


@pytest.fixture
def admin(http):
    return make_user(http, "admin@bank.dz", "an admin master password")


def db_path(settings):
    return settings.database_url.removeprefix("sqlite:///")
