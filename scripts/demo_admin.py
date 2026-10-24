"""Admin + audit demo:  python scripts/demo_admin.py http://127.0.0.1:8000 /path/to/server.db
Server must run with PWVAULT_ADMIN_EMAILS=admin@bank.dz and the same database."""
import sqlite3
import sys

import httpx

from pwvault import KdfParams
from pwvault.remote import RemoteError, RemoteVault

BASE, DB = sys.argv[1], sys.argv[2]
kdf = KdfParams(time_cost=2, memory_cost_kib=19456, parallelism=1)
with httpx.Client(base_url=BASE, timeout=30) as http:
    RemoteVault.register(http, "admin@bank.dz", "admin master passphrase", kdf)
    RemoteVault.register(http, "employee@bank.dz", "employee master passphrase", kdf)
    admin = RemoteVault.login(http, "admin@bank.dz", "admin master passphrase")
    emp = RemoteVault.login(http, "employee@bank.dz", "employee master passphrase")
    print("roles:", admin.me()["role"], "/", emp.me()["role"])

    emp.add_entry("core-banking.bank.dz", "e.benali", "Sup3r-Secret-42")
    try:
        emp.admin_users()
    except RemoteError as e:
        print("employee calling /admin/users ->", e)
    for _ in range(5):
        try: RemoteVault.login(http, "employee@bank.dz", "guess")
        except RemoteError: pass
    print("employee locked:", [u["locked"] for u in admin.admin_users() if u["email"].startswith("employee")][0])
    admin.admin_unlock([u["id"] for u in admin.admin_users() if u["role"] == "employee"][0])

    print("\n--- audit trail (newest last) ---")
    for r in reversed(admin.audit(50)):
        print(f'{r["seq"]:>3} {r["ts"]} {r["action"]:<22} {r["detail"]}')
    print("\nverify:", admin.audit_verify())

    print("\n>>> attacker edits the database directly (hides the lockout)...")
    con = sqlite3.connect(DB); con.execute("UPDATE audit_log SET action='auth.login' WHERE action='auth.lockout'"); con.commit(); con.close()
    v = admin.audit_verify()
    print("verify:", {k: v[k] for k in ("valid", "first_bad_seq", "reason")})
