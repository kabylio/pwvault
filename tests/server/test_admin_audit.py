import hashlib
import json
import sqlite3

import pytest

from pwvault.remote import RemoteError, RemoteVault
from pwvault_server import Settings, create_app, security
from .conftest import EMAIL, MASTER, db_path, make_user


def actions(admin):
    return [r["action"] for r in admin.audit(500)]


# ------------------------------------------------------------------ roles
def test_only_configured_email_becomes_admin(admin, alice):
    assert admin.me()["role"] == "admin"
    assert alice.me()["role"] == "employee"


def test_employee_and_anonymous_cannot_use_admin_api(http, alice):
    for method, path in [("GET", "/admin/users"), ("GET", "/admin/audit"),
                         ("GET", "/admin/audit/verify")]:
        with pytest.raises(RemoteError) as e:
            alice._req(method, path)
        assert e.value.status == 403
        assert http.request(method, path).status_code == 401
    with pytest.raises(RemoteError) as e:
        alice._req("POST", f"/admin/users/{alice.me()['id']}/disable")
    assert e.value.status == 403


def test_admin_lists_users_without_any_secret_material(admin, alice):
    alice.add_entry("a.com", "u", "pw")
    users = {u["email"]: u for u in admin.admin_users()}
    assert users[EMAIL]["entry_count"] == 1 and users[EMAIL]["role"] == "employee"
    assert set(users[EMAIL]) == {"id", "email", "role", "disabled", "locked",
                                 "totp_enabled", "entry_count", "created_at"}


def test_admin_cannot_read_vault_contents(admin, alice):
    eid = alice.add_entry("secret.com", "u", "pw")
    with pytest.raises(RemoteError) as e:
        admin.get_entry(eid)                       # still 404: isolation applies to admins too
    assert e.value.status == 404


def test_role_change_and_self_protection(admin, alice):
    alice_id, admin_id = alice.me()["id"], admin.me()["id"]
    admin.admin_set_role(alice_id, "admin")
    assert alice.admin_users()                     # promoted: now allowed
    admin.admin_set_role(alice_id, "employee")
    with pytest.raises(RemoteError) as e:
        alice.admin_users()
    assert e.value.status == 403
    for call in (lambda: admin.admin_set_role(admin_id, "employee"),
                 lambda: admin.admin_disable(admin_id)):
        with pytest.raises(RemoteError) as e:
            call()
        assert e.value.status == 409               # no accidental admin lock-out
    with pytest.raises(RemoteError) as e:
        admin._req("PUT", f"/admin/users/{alice_id}/role", json={"role": "root"})
    assert e.value.status == 422


def test_disable_revokes_sessions_and_blocks_login(http, admin, alice):
    alice_id = alice.me()["id"]
    admin.admin_disable(alice_id)
    with pytest.raises(RemoteError) as e:
        alice.me()                                 # live token died immediately
    assert e.value.status == 401
    with pytest.raises(RemoteError) as e:
        RemoteVault.login(http, EMAIL, MASTER)
    assert e.value.status == 403
    with pytest.raises(RemoteError) as e:          # wrong password reveals nothing
        RemoteVault.login(http, EMAIL, "a wrong master password")
    assert e.value.status == 401
    admin.admin_enable(alice_id)
    assert RemoteVault.login(http, EMAIL, MASTER).me()["email"] == EMAIL


def test_admin_can_unlock_locked_account(http, admin, alice):
    alice_id = alice.me()["id"]
    for _ in range(5):
        with pytest.raises(RemoteError):
            RemoteVault.login(http, EMAIL, "wrong password attempt")
    with pytest.raises(RemoteError) as e:
        RemoteVault.login(http, EMAIL, MASTER)
    assert e.value.status == 429
    assert [u for u in admin.admin_users() if u["email"] == EMAIL][0]["locked"] is True
    admin.admin_unlock(alice_id)
    assert RemoteVault.login(http, EMAIL, MASTER)


# ------------------------------------------------------------------ audit
def test_security_events_are_recorded(http, admin, alice):
    eid = alice.add_entry("a.com", "u", "pw")
    alice.update_entry(eid, password="pw2")
    alice.delete_entry(eid)
    alice.change_master_password(MASTER, "a brand new master password")
    for _ in range(5):
        with pytest.raises(RemoteError):
            RemoteVault.login(http, EMAIL, "wrong password attempt")
    with pytest.raises(RemoteError):
        RemoteVault.login(http, "ghost@bank.dz", MASTER)
    seen = set(actions(admin))
    assert {"auth.register", "auth.login", "entry.create", "entry.update", "entry.delete",
            "auth.failure", "auth.lockout", "auth.password_changed"} <= seen


def test_admin_actions_are_audited_with_actor_and_target(admin, alice):
    aid = alice.me()["id"]
    admin.admin_set_role(aid, "admin")
    rec = [r for r in admin.audit() if r["action"] == "admin.role_change"][0]
    assert rec["actor_id"] == admin.me()["id"] and rec["target_id"] == aid
    assert json.loads(rec["detail"]) == {"new": "admin", "old": "employee"}
    assert rec["ip"]


def test_audit_log_never_contains_secrets(admin, alice):
    alice.add_entry("topsecret.example", "carol", "Sup3rS3cretValue!", "private note")
    alice.setup_2fa(MASTER)
    blob = json.dumps(admin.audit(500))
    for needle in ("Sup3rS3cretValue", "topsecret", "carol", "private note", MASTER,
                   "alice@bank.dz"):
        assert needle not in blob


def test_audit_is_newest_first_and_paginates(admin, alice):
    recs = admin.audit(500)
    assert [r["seq"] for r in recs] == sorted((r["seq"] for r in recs), reverse=True)
    page = admin.audit(limit=2)
    older = admin.audit(limit=2, before_seq=page[-1]["seq"])
    assert all(o["seq"] < page[-1]["seq"] for o in older)


def test_untouched_chain_verifies(admin, alice):
    v = admin.audit_verify()
    assert v["valid"] and v["checked"] >= 3 and v["head_hash"] and len(v["head_hash"]) == 64


def _tamper(settings, sql, args=()):
    con = sqlite3.connect(db_path(settings))
    con.execute(sql, args); con.commit(); con.close()


def test_editing_a_record_is_detected(admin, alice, settings):
    _tamper(settings, "UPDATE audit_log SET action='auth.nothing_happened' WHERE seq=2")
    v = admin.audit_verify()
    assert v["valid"] is False and v["first_bad_seq"] == 2
    assert "modified" in v["reason"]


def test_deleting_a_record_is_detected(admin, alice, settings):
    _tamper(settings, "DELETE FROM audit_log WHERE seq=2")
    v = admin.audit_verify()
    assert v["valid"] is False and "gap" in v["reason"]


def test_attacker_without_server_key_cannot_forge_a_valid_chain(admin, alice, settings):
    """Even recomputing a plain SHA-256 'hash' for an edited record fails: the
    chain is an HMAC keyed with a secret that is not in the database."""
    con = sqlite3.connect(db_path(settings))
    row = con.execute("SELECT seq,ts,actor_id,action,target_id,detail,ip,prev_hash FROM audit_log WHERE seq=2").fetchone()
    forged = hashlib.sha256((row[7] + "|forged").encode()).hexdigest()
    con.execute("UPDATE audit_log SET action='forged', hash=? WHERE seq=2", (forged,))
    con.commit(); con.close()
    assert admin.audit_verify()["valid"] is False


def test_wrong_server_key_fails_verification(admin, alice, settings, tmp_path):
    other = Settings(jwt_secret=settings.jwt_secret, server_key=bytes(32),
                     database_url=settings.database_url)
    from fastapi.testclient import TestClient
    with TestClient(create_app(other)) as c2:
        assert c2.app.state.audit.verify()["valid"] is False


# -------------------------------------------------------------- migration
def test_old_database_is_migrated_in_place(settings, tmp_path):
    create_app(settings)                           # creates the current schema
    con = sqlite3.connect(db_path(settings))
    con.execute("ALTER TABLE users DROP COLUMN role")
    con.execute("ALTER TABLE users DROP COLUMN disabled")
    con.commit(); con.close()
    create_app(settings)                           # must re-add them, not crash
    cols = {r[1] for r in sqlite3.connect(db_path(settings)).execute("PRAGMA table_info(users)")}
    assert {"role", "disabled"} <= cols
