import dataclasses
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pwvault.remote import RemoteError, RemoteVault
from pwvault_server import create_app
from .conftest import FAST, db_path, make_user

PW = "a perfectly fine master password"


@pytest.fixture
def invite_http(settings):
    with TestClient(create_app(dataclasses.replace(settings, registration="invite"))) as c:
        yield c


@pytest.fixture
def boss(invite_http):                      # admin@bank.dz is in admin_emails: may always register
    return make_user(invite_http, "admin@bank.dz", PW)


def reg(http, email, code=None):
    RemoteVault.register(http, email, PW, kdf=FAST, invite_code=code)


def test_open_mode_is_unchanged(http):
    reg(http, "anyone@bank.dz")                              # default settings stay open


def test_registration_needs_an_invitation(invite_http, boss):
    for code in (None, "", "not-a-real-code"):
        with pytest.raises(RemoteError) as e:
            reg(invite_http, "new@bank.dz", code)
        assert e.value.status == 403


def test_invite_works_once_and_only_for_its_email(invite_http, boss):
    code = boss.admin_invite("new@bank.dz")["code"]
    with pytest.raises(RemoteError) as e:                    # code is bound to one address
        reg(invite_http, "other@bank.dz", code)
    assert e.value.status == 403
    reg(invite_http, "new@bank.dz", code.upper())            # case-insensitive
    assert RemoteVault.login(invite_http, "new@bank.dz", PW).me()["role"] == "employee"
    with pytest.raises(RemoteError):                         # single use
        reg(invite_http, "new@bank.dz", code)


def test_expired_invite_is_rejected(invite_http, boss, settings):
    code = boss.admin_invite("late@bank.dz")["code"]
    con = sqlite3.connect(db_path(settings))
    con.execute("UPDATE invites SET expires_at='2000-01-01 00:00:00'"); con.commit(); con.close()
    with pytest.raises(RemoteError) as e:
        reg(invite_http, "late@bank.dz", code)
    assert e.value.status == 403


def test_new_invite_replaces_the_old_one(invite_http, boss):
    old = boss.admin_invite("x@bank.dz")["code"]
    new = boss.admin_invite("x@bank.dz")["code"]
    with pytest.raises(RemoteError):
        reg(invite_http, "x@bank.dz", old)
    reg(invite_http, "x@bank.dz", new)


def test_only_admins_can_invite_and_existing_users_cannot_be_invited(invite_http, boss):
    code = boss.admin_invite("emp@bank.dz")["code"]
    reg(invite_http, "emp@bank.dz", code)
    emp = RemoteVault.login(invite_http, "emp@bank.dz", PW)
    with pytest.raises(RemoteError) as e:
        emp.admin_invite("friend@bank.dz")
    assert e.value.status == 403
    with pytest.raises(RemoteError) as e:
        boss.admin_invite("emp@bank.dz")
    assert e.value.status == 409


def test_codes_are_stored_hashed_and_not_audited(invite_http, boss, settings):
    code = boss.admin_invite("h@bank.dz")["code"]
    assert code.encode() not in open(db_path(settings), "rb").read()
    log = str(boss.audit(500))
    assert code not in log and "h@bank.dz" not in log and "admin.invite_created" in log
