import sqlite3

import pytest

from pwvault.remote import RemoteError
from .conftest import MASTER


def test_crud_roundtrip(alice):
    eid = alice.add_entry("github.com", "alice", "s3cret!", "my notes")
    e = alice.get_entry(eid)
    assert (e.site, e.username, e.password, e.notes) == \
           ("github.com", "alice", "s3cret!", "my notes")
    alice.update_entry(eid, password="n3w")
    assert alice.get_entry(eid).password == "n3w"
    assert [x.site for x in alice.list_entries()] == ["github.com"]
    alice.delete_entry(eid)
    assert alice.list_entries() == []


def test_search(alice):
    alice.add_entry("github.com", "alice", "a")
    alice.add_entry("gitlab.com", "bob", "b")
    assert len(alice.find("git")) == 2
    assert [e.site for e in alice.find("bob")] == ["gitlab.com"]


def test_server_database_contains_no_plaintext(http, alice, settings):
    alice.add_entry("topsecretbank.example", "carol_the_user", "Sup3rS3cretValue!",
                    notes="private note")
    raw = open(settings.database_url.removeprefix("sqlite:///"), "rb").read()
    for needle in (b"topsecretbank", b"carol_the_user", b"Sup3rS3cretValue",
                   b"private note", MASTER.encode()):
        assert needle not in raw


def test_users_cannot_see_or_touch_each_others_entries(alice, bob):
    eid = alice.add_entry("alice-private.com", "alice", "pw")
    assert bob.list_entries() == []
    for call in (lambda: bob.get_entry(eid),
                 lambda: bob.update_entry(eid, password="hacked"),
                 lambda: bob.delete_entry(eid)):
        with pytest.raises(RemoteError) as e:
            call()
        assert e.value.status == 404          # indistinguishable from "missing"
    assert alice.get_entry(eid).password == "pw"   # untouched


def test_other_users_cannot_decrypt_even_if_blob_is_stolen(http, alice, bob):
    """Even with the raw ciphertext, a different user's vault key fails."""
    from pwvault.vault import VaultError
    eid = alice.add_entry("a.com", "u", "pw")
    row = alice._req("GET", f"/entries/{eid}")
    with pytest.raises(VaultError):
        bob._open(row)


def test_server_side_tampering_is_detected(http, alice, settings):
    from pwvault.vault import VaultError
    eid = alice.add_entry("a.com", "u", "pw")
    db = settings.database_url.removeprefix("sqlite:///")
    con = sqlite3.connect(db)
    (blob,) = con.execute("SELECT blob FROM entries WHERE id=?", (eid,)).fetchone()
    bad = bytearray(blob); bad[20] ^= 0xFF
    con.execute("UPDATE entries SET blob=? WHERE id=?", (bytes(bad), eid))
    con.commit(); con.close()
    with pytest.raises(VaultError, match="tampered"):
        alice.get_entry(eid)


def test_swapping_blobs_between_entries_is_detected(http, alice, settings):
    from pwvault.vault import VaultError
    a = alice.add_entry("a.com", "u", "pa")
    b = alice.add_entry("b.com", "u", "pb")
    con = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    (blob_a,) = con.execute("SELECT blob FROM entries WHERE id=?", (a,)).fetchone()
    con.execute("UPDATE entries SET blob=? WHERE id=?", (blob_a, b))
    con.commit(); con.close()
    with pytest.raises(VaultError):
        alice.get_entry(b)


def test_version_conflict_detected(alice):
    eid = alice.add_entry("a.com", "u", "pw")
    stale = alice.get_entry(eid)                       # version 1
    alice.update_entry(eid, password="first")          # -> version 2
    with pytest.raises(RemoteError) as e:
        alice._req("PUT", f"/entries/{eid}",
                   json={"blob": alice._seal(stale), "version": stale.version})
    assert e.value.status == 409


def test_invalid_entry_input_rejected(alice):
    for payload in ({"id": "not-a-uuid", "blob": "AAAA"},
                    {"id": "6f1c1e0e-5b1c-4a55-9d6a-1d5c2f0f6a11", "blob": "!!!"},
                    {"id": "6f1c1e0e-5b1c-4a55-9d6a-1d5c2f0f6a11", "blob": "AAAA"}):  # too short
        with pytest.raises(RemoteError) as e:
            alice._req("POST", "/entries", json=payload)
        assert e.value.status == 422


def test_session_closed_after_logout(alice):
    from pwvault.vault import VaultError
    alice.logout()
    with pytest.raises(VaultError):
        alice.list_entries()
