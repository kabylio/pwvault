import dataclasses

import httpx
import pytest
from fastapi.testclient import TestClient

from pwvault import breach
from pwvault.remote import RemoteError, RemoteVault
from pwvault_server import create_app
from .conftest import FAST

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PREFIX, SUFFIX = "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
BODY = ("0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
        f"{SUFFIX}:9545824\r\n"
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n")      # :0 = padding row


@pytest.fixture
def upstream():
    return {"calls": [], "status": 200}


@pytest.fixture
def client(settings, upstream):
    def handler(request: httpx.Request) -> httpx.Response:
        upstream["calls"].append(request)
        return httpx.Response(upstream["status"], text=BODY)
    on = dataclasses.replace(settings, breach_check=True)
    with TestClient(create_app(on, hibp_transport=httpx.MockTransport(handler))) as c:
        yield c


def user(client):
    RemoteVault.register(client, "u@bank.dz", "a long master password", kdf=FAST)
    return RemoteVault.login(client, "u@bank.dz", "a long master password")


def test_helpers():
    assert breach.split_hash("password") == (PREFIX, SUFFIX)
    assert breach.count_in_range(BODY, SUFFIX) == 9545824
    assert breach.count_in_range(BODY, "0" * 35) == 0
    assert breach.count_in_range(BODY, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC") == 0


def test_breached_and_clean_passwords(client):
    u = user(client)
    assert u.breach_count("password") == 9545824
    assert u.breach_count("zq9!never-seen-before-Lm2#") == 0


def test_only_the_prefix_ever_leaves_the_server(client, upstream):
    user(client).breach_count("password")
    (req,) = upstream["calls"]
    assert str(req.url).endswith("/range/" + PREFIX)
    assert req.headers["add-padding"] == "true"
    assert req.url.path == "/range/" + PREFIX            # nothing but the 5-char prefix
    assert SUFFIX not in str(req.url) and not req.url.query
    assert "authorization" not in req.headers          # no user identity upstream


def test_requires_login(client):
    assert client.get(f"/breach/range/{PREFIX}").status_code == 401


def test_disabled_by_default(http):
    u = user(http)
    with pytest.raises(RemoteError) as e:
        u.breach_count("password")
    assert e.value.status == 503
    assert http.get("/breach/status", headers={"Authorization": f"Bearer {u._token}"}).json() == {"enabled": False}


@pytest.mark.parametrize("bad", ["abcd", "abcdef", "ZZZZZ", "5BAA6%2F..", "..%2Fetc"])
def test_prefix_is_strictly_validated(client, bad):
    u = user(client)
    with pytest.raises(RemoteError) as e:
        u._req("GET", f"/breach/range/{bad}")
    assert e.value.status in (404, 422)


def test_upstream_failure_is_reported_as_502(client, upstream):
    u = user(client)
    upstream["status"] = 500
    with pytest.raises(RemoteError) as e:
        u.breach_count("password")
    assert e.value.status == 502
