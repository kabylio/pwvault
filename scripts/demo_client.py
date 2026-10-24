"""End-to-end demo against a running server:  python scripts/demo_client.py
Start the server first (see README). Uses a throw-away account."""
import secrets
import sys

import httpx
import pyotp

from pwvault import KdfParams
from pwvault.remote import OtpRequired, RemoteError, RemoteVault

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
email = f"demo-{secrets.token_hex(3)}@bank.dz"
master = "demo master passphrase 2026"
kdf = KdfParams(time_cost=3, memory_cost_kib=65536, parallelism=4)

with httpx.Client(base_url=BASE, timeout=30) as http:
    print("1. register + login");  RemoteVault.register(http, email, master, kdf)
    vault = RemoteVault.login(http, email, master)

    print("2. add encrypted entries")
    gh = vault.add_entry("github.com", "alice", "S3cret-Pass!", "work account")
    vault.add_entry("intranet.bank.dz", "a.benali", "Another-One-42")
    print("   ", [(e.site, e.username) for e in vault.list_entries()])

    print("3. what the SERVER stores for that entry (ciphertext only):")
    print("   ", vault._req("GET", f"/entries/{gh}")["blob"][:60], "...")

    print("4. enable 2FA")
    secret, uri = vault.setup_2fa(master)
    codes = vault.enable_2fa(pyotp.TOTP(secret).now())
    print("    recovery codes:", codes[:2], "...")

    print("5. login now requires a second factor")
    try:
        RemoteVault.login(http, email, master)
    except OtpRequired:
        print("    -> server answered: otp_required")
    session = RemoteVault.login(http, email, master, recovery_code=codes[0])
    print("    -> logged in with a recovery code; entries:", len(session.list_entries()))

    print("6. wrong password is refused")
    try:
        RemoteVault.login(http, email, "not my password at all")
    except RemoteError as exc:
        print("    ->", exc)
print("done.")
