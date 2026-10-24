import jwt
import pytest

from pwvault import KdfParams
from pwvault.remote import RemoteError, RemoteVault
from pwvault_server import security
from .conftest import EMAIL, FAST, MASTER, make_user


def test_register_login_me(http, alice):
    me = alice.me()
    assert me["email"] == EMAIL and me["totp_enabled"] is False


def test_wrong_password_rejected(http, alice):
    with pytest.raises(RemoteError) as e:
        RemoteVault.login(http, EMAIL, "a completely wrong password")
    assert e.value.status == 401


def test_unknown_user_looks_identical_to_wrong_password(http, alice):
    with pytest.raises(RemoteError) as unknown:
        RemoteVault.login(http, "nobody@bank.dz", MASTER)
    with pytest.raises(RemoteError) as wrong:
        RemoteVault.login(http, EMAIL, "a completely wrong password")
    assert (unknown.value.status, unknown.value.detail) == \
           (wrong.value.status, wrong.value.detail)


def test_prelogin_does_not_reveal_whether_account_exists(http, alice):
    real = http.post("/auth/prelogin", json={"email": EMAIL}).json()
    fake = http.post("/auth/prelogin", json={"email": "ghost@bank.dz"}).json()
    assert set(real) == set(fake) and set(real["kdf"]) == set(fake["kdf"])
    # the fake salt is stable, so repeated probing can't tell them apart
    assert fake == http.post("/auth/prelogin", json={"email": "ghost@bank.dz"}).json()


def test_duplicate_email_rejected(http, alice):
    with pytest.raises(RemoteError) as e:
        RemoteVault.register(http, EMAIL.upper(), MASTER, kdf=FAST)  # case-insens.
    assert e.value.status == 409


def test_weak_kdf_rejected_by_server(http):
    with pytest.raises(RemoteError) as e:
        RemoteVault.register(http, "weak@bank.dz", MASTER,
                             kdf=KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1))
    assert e.value.status == 422


def test_malformed_input_rejected(http):
    r = http.post("/auth/register", json={"email": "not-an-email", "auth_key": "x",
                                          "salt": "x", "kdf": {}, "wrapped_key": "x"})
    assert r.status_code == 422


def test_missing_and_garbage_tokens_rejected(http, alice):
    assert http.get("/auth/me").status_code == 401
    assert http.get("/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert http.get("/entries").status_code == 401


def test_expired_token_rejected(http, alice, settings):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    claims = {"sub": alice.me()["id"], "tv": 0, "iat": now - timedelta(hours=2),
              "exp": now - timedelta(hours=1)}
    token = jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
    assert http.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_signed_with_other_secret_or_alg_none_rejected(http, alice):
    uid = alice.me()["id"]
    forged = jwt.encode({"sub": uid, "tv": 0, "iat": 1, "exp": 4102444800},
                        "x" * 48, algorithm="HS256")
    assert http.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_tok = jwt.encode({"sub": uid, "tv": 0, "iat": 1, "exp": 4102444800},
                          None, algorithm="none")
    assert http.get("/auth/me", headers={"Authorization": f"Bearer {none_tok}"}).status_code == 401


def test_account_locks_after_repeated_failures(http, alice, settings):
    import sqlite3
    for _ in range(5):
        with pytest.raises(RemoteError):
            RemoteVault.login(http, EMAIL, "wrong password attempt")
    with pytest.raises(RemoteError) as e:          # even the RIGHT password now
        RemoteVault.login(http, EMAIL, MASTER)
    assert e.value.status == 429
    # ...until the lockout window passes (expire it in the database)
    con = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    con.execute("UPDATE users SET locked_until = '2000-01-01 00:00:00'"); con.commit(); con.close()
    assert RemoteVault.login(http, EMAIL, MASTER).me()["email"] == EMAIL


def test_successful_login_resets_failure_counter(http, alice):
    for _ in range(4):
        with pytest.raises(RemoteError):
            RemoteVault.login(http, EMAIL, "wrong password attempt")
    RemoteVault.login(http, EMAIL, MASTER)
    for _ in range(4):                      # 4 more would lock if not reset
        with pytest.raises(RemoteError):
            RemoteVault.login(http, EMAIL, "wrong password attempt")
    assert RemoteVault.login(http, EMAIL, MASTER)


def test_change_master_password(http, alice):
    eid = alice.add_entry("github.com", "alice", "pw1")
    old_token = alice._token
    alice.change_master_password(MASTER, "a brand new master password")

    # old token is revoked, old password no longer works
    assert http.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, MASTER)
    # new password works and the data is still readable
    again = RemoteVault.login(http, EMAIL, "a brand new master password")
    assert again.get_entry(eid).password == "pw1"


def test_change_master_password_needs_correct_current_password(http, alice):
    with pytest.raises(RemoteError) as e:
        alice.change_master_password("not my current password", "a brand new master password")
    assert e.value.status == 401
