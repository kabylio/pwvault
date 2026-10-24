import json
import sqlite3

import pytest

from pwvault import crypto, sharing
from pwvault.crypto import DecryptionError
from pwvault.remote import RemoteError, RemoteVault, _b64d, _b64e
from pwvault.vault import VaultError
from .conftest import FAST, db_path, make_user

BLOB = _b64e(bytes(40))      # any syntactically valid ciphertext, for payload-shape tests


@pytest.fixture
def carol(http):
    return make_user(http, "carol@bank.dz", "carol master password")


@pytest.fixture
def dave(http):
    return make_user(http, "dave@bank.dz", "dave master password!!")


@pytest.fixture
def team(alice, bob, carol):
    """alice = owner, bob = editor, carol = viewer; two entries."""
    vid = alice.create_shared_vault("Core Banking")
    alice.add_member(vid, "bob@bank.dz", "editor")
    alice.add_member(vid, "carol@bank.dz", "viewer")
    e1 = alice.shared_add_entry(vid, "core-db", "svc", "pw-1", "prod")
    e2 = alice.shared_add_entry(vid, "mainframe", "ops", "pw-2")
    return vid, e1, e2


def sql(settings, query, args=()):
    con = sqlite3.connect(db_path(settings))
    try:
        out = con.execute(query, args).fetchall(); con.commit(); return out
    finally:
        con.close()


# ------------------------------------------------------------ primitives
def test_wrap_unwrap_roundtrip_and_wrong_recipient():
    (sk, pk), (sk2, _) = sharing.generate_keypair(), sharing.generate_keypair()
    blob = sharing.wrap_for(pk, b"vault-key", b"ctx")
    assert sharing.unwrap(sk, blob, b"ctx") == b"vault-key"
    with pytest.raises(DecryptionError):
        sharing.unwrap(sk2, blob, b"ctx")                       # someone else's private key
    with pytest.raises(DecryptionError):
        sharing.unwrap(sk, blob, b"other-context")              # replayed in another context
    bad = bytearray(blob); bad[-1] ^= 1
    with pytest.raises(DecryptionError):
        sharing.unwrap(sk, bytes(bad), b"ctx")                  # tampered
    with pytest.raises(DecryptionError):
        sharing.unwrap(sk, blob[:40], b"ctx")                   # truncated


def test_wrapping_is_randomised_and_low_order_keys_rejected():
    _, pk = sharing.generate_keypair()
    assert sharing.wrap_for(pk, b"x", b"a") != sharing.wrap_for(pk, b"x", b"a")
    with pytest.raises(ValueError):
        sharing.wrap_for(bytes(32), b"x", b"a")                 # all-zero point


def test_fingerprint_format_and_stability():
    _, pk = sharing.generate_keypair()
    fp = sharing.fingerprint(pk)
    assert fp == sharing.fingerprint(pk) and len(fp.split()) == 8
    assert fp != sharing.fingerprint(sharing.generate_keypair()[1])


# ------------------------------------------------------------- keypairs
def test_keypair_created_once_and_stable_across_logins(http, alice):
    assert len(alice._pub) == 32 and alice.me()["public_key"] == _b64e(alice._pub)
    again = RemoteVault.login(http, "alice@bank.dz", "correct horse battery staple")
    assert again._pub == alice._pub and again.my_fingerprint() == alice.my_fingerprint()


def test_keypair_is_immutable(alice):
    with pytest.raises(RemoteError) as e:
        alice._req("PUT", "/auth/keypair", json={"public_key": _b64e(bytes(32)), "wrapped_private_key": BLOB})
    assert e.value.status == 409


def test_account_from_before_sharing_gets_a_keypair_on_next_login(http, alice, settings):
    sql(settings, "UPDATE users SET public_key=NULL, wrapped_private_key=NULL")
    fresh = RemoteVault.login(http, "alice@bank.dz", "correct horse battery staple")
    assert fresh.me()["public_key"] and fresh.create_shared_vault("works")


def test_server_swapping_your_public_key_is_detected_at_login(http, alice, settings):
    sql(settings, "UPDATE users SET public_key=?", (bytes(range(1, 33)),))
    with pytest.raises(VaultError, match="does not match"):
        RemoteVault.login(http, "alice@bank.dz", "correct horse battery staple")


def test_private_key_is_not_readable_by_the_server(alice, settings):
    raw = open(db_path(settings), "rb").read()
    assert alice._priv not in raw and alice._pub in raw          # only the public half is stored


def test_master_password_change_keeps_sharing_working(http, team, bob):
    vid, e1, _ = team
    bob.change_master_password("another long master password", "bob's brand new master password")
    again = RemoteVault.login(http, "bob@bank.dz", "bob's brand new master password")
    assert again.shared_get(vid, e1).password == "pw-1"


# -------------------------------------------------------- vault basics
def test_create_list_and_use_vault(alice):
    vid = alice.create_shared_vault("Treasury")
    assert alice.list_shared_vaults() == [{"id": vid, "name": "Treasury", "role": "owner", "key_version": 1}]
    eid = alice.shared_add_entry(vid, "swift", "ops", "S3cret!", "note")
    e = alice.shared_get(vid, eid)
    assert (e.site, e.username, e.password, e.notes) == ("swift", "ops", "S3cret!", "note")
    alice.shared_update(vid, eid, password="n3w")
    assert alice.shared_get(vid, eid).password == "n3w"
    assert [x.site for x in alice.shared_list(vid)] == ["swift"]
    alice.shared_delete(vid, eid)
    assert alice.shared_list(vid) == []


def test_server_stores_no_plaintext_for_shared_vaults(team, settings):
    raw = open(db_path(settings), "rb").read()
    for needle in (b"Core Banking", b"core-db", b"mainframe", b"pw-1", b"prod"):
        assert needle not in raw


def test_members_can_read_what_others_wrote(team, bob, carol):
    vid, e1, _ = team
    assert bob.shared_get(vid, e1).password == "pw-1"
    assert carol.shared_get(vid, e1).notes == "prod"
    new = bob.shared_add_entry(vid, "swift-gw", "bob", "from-bob")
    assert carol.shared_get(vid, new).password == "from-bob"
    assert {v["name"] for v in carol.list_shared_vaults()} == {"Core Banking"}


# -------------------------------------------------------------- roles
def test_viewer_is_read_only_and_cannot_manage_members(team, carol, dave):
    vid, e1, _ = team
    for call in (lambda: carol.shared_add_entry(vid, "x", "y", "z"),
                 lambda: carol.shared_update(vid, e1, password="hacked"),
                 lambda: carol.shared_delete(vid, e1),
                 lambda: carol.add_member(vid, "dave@bank.dz", "viewer"),
                 lambda: carol.delete_shared_vault(vid)):
        with pytest.raises(RemoteError) as e:
            call()
        assert e.value.status == 403
    assert carol.shared_get(vid, e1).password == "pw-1"


def test_editor_cannot_manage_members_or_delete_vault(team, bob, dave):
    vid, _, _ = team
    for call in (lambda: bob.add_member(vid, "dave@bank.dz", "viewer"),
                 lambda: bob.delete_shared_vault(vid),
                 lambda: bob.set_member_role(vid, bob._uid, "owner")):
        with pytest.raises(RemoteError) as e:
            call()
        assert e.value.status == 403


def test_non_members_cannot_even_tell_the_vault_exists(team, dave):
    vid, e1, _ = team
    assert dave.list_shared_vaults() == []
    for method, path in [("GET", f"/vaults/{vid}/entries"), ("GET", f"/vaults/{vid}/members"),
                         ("GET", f"/vaults/{vid}/entries/{e1}"), ("DELETE", f"/vaults/{vid}")]:
        with pytest.raises(RemoteError) as e:
            dave._req(method, path)
        assert e.value.status == 404


def test_role_changes_and_last_owner_protection(team, alice, bob, carol):
    vid, _, _ = team
    alice.set_member_role(vid, carol._uid, "editor")
    assert carol.shared_add_entry(vid, "now-allowed", "c", "pw")
    with pytest.raises(RemoteError) as e:
        alice.set_member_role(vid, alice._uid, "viewer")          # would leave no owner
    assert e.value.status == 409
    alice.set_member_role(vid, bob._uid, "owner")
    alice.set_member_role(vid, alice._uid, "editor")              # fine now: bob is an owner
    assert bob.list_shared_vaults()[0]["role"] == "owner"


def test_admin_cannot_see_or_open_shared_vaults(http, team, admin):
    vid, _, _ = team
    assert admin.list_shared_vaults() == []
    with pytest.raises(RemoteError) as e:
        admin._req("GET", f"/vaults/{vid}/entries")
    assert e.value.status == 404


# --------------------------------------------------- key substitution
def test_fingerprint_pinning_blocks_a_substituted_key(team, alice, dave):
    vid, _, _ = team
    with pytest.raises(VaultError, match="fingerprint mismatch"):
        alice.add_member(vid, "dave@bank.dz", "viewer", expected_fingerprint="0000 1111 2222 3333 4444 5555 6666 7777")
    assert all(m["email"] != "dave@bank.dz" for m in alice.shared_members(vid))     # nothing was shared
    fp = alice.add_member(vid, "dave@bank.dz", "viewer", expected_fingerprint=dave.my_fingerprint().lower())
    assert fp == dave.my_fingerprint()
    assert dave.list_shared_vaults()[0]["name"] == "Core Banking"


def test_cannot_share_with_unknown_disabled_or_keyless_users(http, team, alice, admin, carol):
    vid, _, _ = team
    RemoteVault.register(http, "nokeys@bank.dz", "never logged in yet", kdf=FAST)       # no keypair
    for email in ("ghost@bank.dz", "nokeys@bank.dz"):
        with pytest.raises(RemoteError) as e:
            alice.add_member(vid, email)
        assert e.value.status == 404
    admin.admin_disable(carol._uid)
    with pytest.raises(RemoteError) as e:
        alice.add_member(vid, "carol@bank.dz")
    assert e.value.status == 404


def test_duplicate_member_rejected(team, alice):
    vid, _, _ = team
    with pytest.raises(RemoteError) as e:
        alice.add_member(vid, "bob@bank.dz")
    assert e.value.status == 409


# -------------------------------------------------- removal = rotation
def test_removed_member_loses_access_and_old_key_is_useless(team, alice, bob, carol):
    vid, e1, e2 = team
    old_key = bob._shared_key(bob._vault_row(vid))                 # what bob legitimately knew
    before = alice._req("GET", f"/vaults/{vid}/entries/{e1}")

    alice.remove_member(vid, bob._uid)

    assert bob.list_shared_vaults() == []
    with pytest.raises(RemoteError) as e:
        bob.shared_get(vid, e1)
    assert e.value.status == 404
    # remaining members still work, entries intact, key rotated
    assert alice.list_shared_vaults()[0]["key_version"] == 2 and alice.list_shared_vaults()[0]["name"] == "Core Banking"
    assert {x.password for x in carol.shared_list(vid)} == {"pw-1", "pw-2"}
    # bob's old key opens NOTHING in the vault any more
    after = alice._req("GET", f"/vaults/{vid}/entries/{e1}")
    assert after["blob"] != before["blob"] and after["version"] == before["version"] + 1
    for v in (1, 2):
        with pytest.raises(DecryptionError):
            crypto.decrypt(old_key, _b64d(after["blob"]), sharing.entry_aad(vid, e1, v))


def test_removed_member_cannot_write_with_a_stale_key(team, alice, bob):
    vid, e1, _ = team
    stale_row = bob._vault_row(vid)
    alice.remove_member(vid, bob._uid)
    with pytest.raises(RemoteError) as e:                          # no longer a member
        bob._req("POST", f"/vaults/{vid}/entries", json={"id": "6f1c1e0e-5b1c-4a55-9d6a-1d5c2f0f6a11", "blob": BLOB, "key_version": stale_row["key_version"]})
    assert e.value.status == 404
    with pytest.raises(RemoteError) as e:                          # a member using the old version
        alice._req("POST", f"/vaults/{vid}/entries", json={"id": "6f1c1e0e-5b1c-4a55-9d6a-1d5c2f0f6a11", "blob": BLOB, "key_version": 1})
    assert e.value.status == 409


def test_rotation_payload_must_be_complete_and_consistent(team, alice, bob, carol):
    vid, e1, e2 = team
    ep = f"/vaults/{vid}/members/{bob._uid}/remove"
    keys = {alice._uid: BLOB, carol._uid: BLOB}
    ents = [{"id": e1, "blob": BLOB, "version": 1}, {"id": e2, "blob": BLOB, "version": 1}]
    cases = [
        ({"member_keys": {alice._uid: BLOB}, "entries": ents}, 422),                   # carol would be locked out
        ({"member_keys": {**keys, bob._uid: BLOB}, "entries": ents}, 422),             # the leaver still gets a key
        ({"member_keys": keys, "entries": ents[:1]}, 422),                             # an entry left under the old key
        ({"member_keys": keys, "entries": ents + ents[:1]}, 422),                      # duplicate entry
        ({"member_keys": keys, "entries": [{**ents[0], "version": 9}, ents[1]]}, 409), # stale entry version
        ({"member_keys": keys, "entries": ents, "key_version": 5}, 409),               # must be current + 1
    ]
    for body, status in cases:
        with pytest.raises(RemoteError) as e:
            alice._req("POST", ep, json={"key_version": 2, "name_blob": BLOB, **body})
        assert e.value.status == status, body
    assert alice.list_shared_vaults()[0]["key_version"] == 1       # nothing half-applied
    assert bob.shared_get(vid, e1).password == "pw-1"              # bob still a member


def test_leaver_cannot_trigger_their_own_removal_and_non_owners_cannot_remove(team, alice, bob, carol):
    vid, _, _ = team
    with pytest.raises(RemoteError) as e:
        alice.remove_member(vid, alice._uid)                       # a leaver must not mint the new key
    assert e.value.status == 409
    with pytest.raises(RemoteError) as e:
        bob.remove_member(vid, carol._uid)                         # editors cannot manage members
    assert e.value.status == 403


def test_vault_delete_removes_everything(team, alice, bob, settings):
    vid, e1, _ = team
    alice.delete_shared_vault(vid)
    assert bob.list_shared_vaults() == []
    assert sql(settings, "SELECT count(*) FROM shared_entries")[0][0] == 0
    assert sql(settings, "SELECT count(*) FROM vault_members")[0][0] == 0


# ---------------------------------------------------------- tampering
def test_server_side_tampering_of_shared_entries_is_detected(team, alice, settings):
    vid, e1, e2 = team
    (blob,) = sql(settings, "SELECT blob FROM shared_entries WHERE id=?", (e1,))[0]
    bad = bytearray(blob); bad[20] ^= 0xFF
    sql(settings, "UPDATE shared_entries SET blob=? WHERE id=?", (bytes(bad), e1))
    with pytest.raises(VaultError, match="tampered"):
        alice.shared_get(vid, e1)
    (b2,) = sql(settings, "SELECT blob FROM shared_entries WHERE id=?", (e2,))[0]
    sql(settings, "UPDATE shared_entries SET blob=? WHERE id=?", (b2, e1))      # swap ciphertexts
    with pytest.raises(VaultError):
        alice.shared_get(vid, e1)


def test_a_wrapped_key_moved_to_another_member_is_useless(team, alice, bob, settings):
    vid, _, _ = team
    (alice_key,) = sql(settings, "SELECT wrapped_key FROM vault_members WHERE user_id=?", (alice._uid,))[0]
    sql(settings, "UPDATE vault_members SET wrapped_key=? WHERE user_id=?", (alice_key, bob._uid))
    with pytest.raises(VaultError):
        bob.list_shared_vaults()


def test_shared_entry_version_conflict(team, alice, bob):
    vid, e1, _ = team
    stale = alice._open_shared(alice._shared_key(alice._vault_row(vid)), vid, alice._req("GET", f"/vaults/{vid}/entries/{e1}"))
    bob.shared_update(vid, e1, password="first")
    row = alice._vault_row(vid)
    with pytest.raises(RemoteError) as e:
        alice._req("PUT", f"/vaults/{vid}/entries/{e1}", json={
            "version": stale.version, "key_version": row["key_version"],
            "blob": alice._seal_shared(alice._shared_key(row), vid, stale, row["key_version"])})
    assert e.value.status == 409


# ------------------------------------------------------- audit & schema
def test_sharing_events_are_audited_without_secrets(team, alice, bob, admin):
    vid, _, _ = team
    alice.remove_member(vid, bob._uid)
    log = admin.audit(500)
    seen = {r["action"] for r in log}
    assert {"auth.keypair_created", "vault.create", "vault.member_add", "vault.entry_create",
            "vault.member_removed"} <= seen
    removed = [r for r in log if r["action"] == "vault.member_removed"][0]
    assert json.loads(removed["detail"])["new_key_version"] == 2
    blob = json.dumps(log)
    for needle in ("Core Banking", "core-db", "pw-1", "mainframe"):
        assert needle not in blob


def test_old_database_gets_the_new_columns(settings):
    from pwvault_server import create_app
    create_app(settings)
    sql(settings, "ALTER TABLE users DROP COLUMN public_key")
    sql(settings, "ALTER TABLE users DROP COLUMN wrapped_private_key")
    create_app(settings)
    cols = {r[1] for r in sql(settings, "PRAGMA table_info(users)")}
    assert {"public_key", "wrapped_private_key"} <= cols
