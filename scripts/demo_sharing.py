"""Shared-vault demo:  python scripts/demo_sharing.py http://127.0.0.1:8000
Uses throw-away accounts. Shows sharing, roles, and key rotation on removal."""
import secrets
import sys

import httpx

from pwvault import KdfParams, crypto, sharing
from pwvault.remote import RemoteError, RemoteVault, _b64d

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
tag = secrets.token_hex(3)
kdf = KdfParams(time_cost=2, memory_cost_kib=19456, parallelism=1)


def user(name):
    email = f"{name}-{tag}@bank.dz"
    with_pw = f"{name} demo master passphrase"
    RemoteVault.register(httpx.Client(base_url=BASE, timeout=30), email, with_pw, kdf)
    return email, RemoteVault.login(httpx.Client(base_url=BASE, timeout=30), email, with_pw)


(a_mail, alice), (b_mail, bob), (c_mail, carol) = user("alice"), user("bob"), user("carol")
print("1. Alice creates 'Core Banking' and shares it (fingerprints pinned, as if read out by phone)")
vid = alice.create_shared_vault("Core Banking")
alice.add_member(vid, b_mail, "editor", expected_fingerprint=bob.my_fingerprint())
alice.add_member(vid, c_mail, "viewer", expected_fingerprint=carol.my_fingerprint())
eid = alice.shared_add_entry(vid, "core-db", "svc_account", "Pr0d-Secret-77")
print("   Bob (editor) reads:", bob.shared_get(vid, eid).password)
print("   Carol (viewer) reads:", carol.shared_get(vid, eid).password)

print("2. Roles are enforced")
try:
    carol.shared_add_entry(vid, "x", "y", "z")
except RemoteError as e:
    print("   viewer trying to write ->", e)

print("3. What the server holds for that entry (ciphertext only):")
print("  ", alice._req("GET", f"/vaults/{vid}/entries/{eid}")["blob"][:60], "...")

print("4. Bob leaves the team. Alice removes him; the vault key is ROTATED")
bobs_old_key = bob._shared_key(bob._vault_row(vid))          # what Bob legitimately knew
alice.remove_member(vid, bob._uid)
print("   key version now:", alice.list_shared_vaults()[0]["key_version"])
try:
    bob.shared_get(vid, eid)
except RemoteError as e:
    print("   Bob reading ->", e)
new_blob = _b64d(alice._req("GET", f"/vaults/{vid}/entries/{eid}")["blob"])
try:
    crypto.decrypt(bobs_old_key, new_blob, sharing.entry_aad(vid, eid, 2))
except Exception as e:
    print("   Bob's old key on the re-encrypted entry -> fails (", type(e).__name__, ")")
print("   Carol still reads:", carol.shared_get(vid, eid).password)
