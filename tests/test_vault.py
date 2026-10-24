import sqlite3

import pytest

from pwvault import (InvalidMasterPassword, Vault, VaultError,
                     WeakPasswordError)
from .conftest import FAST_KDF, MASTER


def make(path):
    return Vault.create(path, MASTER, kdf=FAST_KDF)


def test_create_and_reopen(vault_path):
    v = make(vault_path)
    eid = v.add_entry("github.com", "alice", "p@ss")
    v.lock()
    with Vault.open(vault_path, MASTER) as v2:
        e = v2.get_entry(eid)
        assert (e.site, e.username, e.password) == ("github.com", "alice", "p@ss")


def test_wrong_master_password_rejected(vault_path):
    make(vault_path).lock()
    with pytest.raises(InvalidMasterPassword):
        Vault.open(vault_path, "totally wrong password")


def test_weak_master_password_rejected(vault_path):
    with pytest.raises(WeakPasswordError):
        Vault.create(vault_path, "short", kdf=FAST_KDF)


def test_cannot_overwrite_existing_vault(vault_path):
    make(vault_path).lock()
    with pytest.raises(FileExistsError):
        make(vault_path)


def test_nothing_sensitive_in_plaintext_on_disk(vault_path):
    v = make(vault_path)
    v.add_entry("secretbank.example", "bob_the_user", "Sup3rS3cretValue!",
                notes="private note")
    v.lock()
    raw = vault_path.read_bytes()
    for needle in (b"secretbank", b"bob_the_user", b"Sup3rS3cretValue",
                   b"private note", MASTER.encode()):
        assert needle not in raw


def test_search_update_delete(vault_path):
    with make(vault_path) as v:
        a = v.add_entry("github.com", "alice", "x")
        v.add_entry("gitlab.com", "bob", "y")
        assert len(v.find("git")) == 2
        assert [e.site for e in v.find("alice")] == ["github.com"]
        v.update_entry(a, password="new", notes="n")
        assert v.get_entry(a).password == "new"
        assert v.delete_entry(a) is True
        assert v.delete_entry(a) is False
        with pytest.raises(KeyError):
            v.get_entry(a)


def test_update_rejects_unknown_field(vault_path):
    with make(vault_path) as v:
        eid = v.add_entry("a", "b", "c")
        with pytest.raises(ValueError):
            v.update_entry(eid, hacker="1")


def test_change_master_password(vault_path):
    v = make(vault_path)
    eid = v.add_entry("site", "u", "pw")
    v.change_master_password(MASTER, "a brand new master password")
    v.lock()
    with pytest.raises(InvalidMasterPassword):
        Vault.open(vault_path, MASTER)
    with Vault.open(vault_path, "a brand new master password") as v2:
        assert v2.get_entry(eid).password == "pw"


def test_change_master_requires_correct_old_password(vault_path):
    with make(vault_path) as v:
        with pytest.raises(InvalidMasterPassword):
            v.change_master_password("not the old one!!", "another long password")


def test_swapping_ciphertexts_between_rows_is_detected(vault_path):
    v = make(vault_path)
    a = v.add_entry("a.com", "u", "pa")
    b = v.add_entry("b.com", "u", "pb")
    v.lock()
    con = sqlite3.connect(vault_path)
    (blob_a,) = con.execute("SELECT blob FROM entries WHERE id=?", (a,)).fetchone()
    con.execute("UPDATE entries SET blob=? WHERE id=?", (blob_a, b))
    con.commit(); con.close()
    with Vault.open(vault_path, MASTER) as v2:
        with pytest.raises(VaultError, match="tampered"):
            v2.get_entry(b)


def test_modified_ciphertext_is_detected(vault_path):
    v = make(vault_path)
    a = v.add_entry("a.com", "u", "pa")
    v.lock()
    con = sqlite3.connect(vault_path)
    (blob,) = con.execute("SELECT blob FROM entries WHERE id=?", (a,)).fetchone()
    bad = bytearray(blob); bad[20] ^= 0xFF
    con.execute("UPDATE entries SET blob=? WHERE id=?", (bytes(bad), a))
    con.commit(); con.close()
    with Vault.open(vault_path, MASTER) as v2:
        with pytest.raises(VaultError):
            v2.get_entry(a)


def test_locked_vault_refuses_access(vault_path):
    v = make(vault_path)
    v.lock()
    assert v.is_locked
    with pytest.raises(Exception):
        v.add_entry("a", "b", "c")
