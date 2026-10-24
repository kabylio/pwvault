# pwvault

A security-first password vault (v0.3), in two parts that share one crypto core:

* **`pwvault`**: the local CLI vault (encrypted SQLite file, master password).
* **`pwvault_server`**: a **zero-knowledge REST API** (FastAPI) with accounts,
  JWT sessions, TOTP and WebAuthn passkeys, encrypted recovery, lockout and per-user isolation.
  `pwvault.remote.RemoteVault` is the client; it does all encryption locally.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what is and isn't protected.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pwvault                 # creates ~/.pwvault/vault.db on first run
python -m pwvault --vault ./my.db # or choose a location
python -m pytest                  # run the test-suite
```
To migrate the old prototype, choose menu option **8** and give it the old
`mykeys.key` and `password.pass` files, then securely delete them.

## Deploy with Docker (one command)
```bash
python scripts/gen_secrets.py > .env          # JWT secret + server key
echo "PWVAULT_ADMIN_EMAILS=you@example.dz" >> .env
docker compose up -d --build
# open https://localhost  (accept Caddy's local certificate once)
```
`app` runs as a non-root user with a read-only filesystem, all Linux
capabilities dropped and **no published port**; only the `proxy` (Caddy, TLS +
HSTS) can reach it, which is what makes trusting `X-Forwarded-For` safe. Data
lives in the `vault-data` volume. **Back up that volume and your `.env`**: the
`PWVAULT_SERVER_KEY` also protects the audit chain and TOTP secrets, so losing it
makes both unverifiable. For a real deployment use the bank's hostname in the
`Caddyfile` (or its own reverse proxy/WAF) and PostgreSQL instead of SQLite.

## CI
`.github/workflows/ci.yml` runs on every push: the test-suite (Python 3.11 and
3.12 plus Node for the browser-crypto interop), `bandit` static analysis,
`pip-audit` for vulnerable dependencies, a check that no `.env`/`.key`/`.db`
file is committed, and a Docker build. Locally: `pip install -r requirements-dev.txt`.

## Run the server (without Docker)
```bash
python scripts/gen_secrets.py            # prints PWVAULT_JWT_SECRET / PWVAULT_SERVER_KEY
export PWVAULT_JWT_SECRET=...  PWVAULT_SERVER_KEY=...      # (Windows: set / $env:)
uvicorn pwvault_server.app:create_app --factory --port 8000
# web UI:               http://127.0.0.1:8000/   (served by the same process)
# interactive API docs: http://127.0.0.1:8000/docs
python scripts/demo_client.py            # end-to-end demo (second terminal)
```
Always put it behind HTTPS in production.

## API
| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | create account (client sends auth key, salt, KDF params, wrapped vault key) |
| POST | `/auth/prelogin` | get salt + KDF params (fake but stable for unknown e-mails) |
| POST | `/auth/login` | auth key (+ `otp` or `recovery_code` if 2FA) -> 15-min JWT |
| GET | `/auth/me` | current account |
| POST | `/auth/2fa/setup`, `/enable`, `/disable` | TOTP setup and disable require the master-password proof; enable returns 8 recovery codes shown once |
| `/auth/passkeys/*` | add, list, remove and use WebAuthn passkeys as a second factor after the master password |
| `/auth/recovery/*` | set a user-held recovery key or re-wrap the vault key with a new master password |
| POST | `/auth/change-password` | re-wrap vault key, revoke all tokens; requires a second factor when 2FA is enabled |
| GET/POST | `/entries` | list / create encrypted entries |
| GET/PUT/DELETE | `/entries/{id}` | read / update (needs `version`) / delete |
| GET | `/entries/{id}/history` | list up to 10 encrypted personal-entry revisions |

## Web UI (`pwvault_server/static/`)
Plain HTML/CSS/JS, no build step. Argon2id runs in the browser as WebAssembly
(`hash-wasm`, vendored) and everything else uses the browser's WebCrypto, so the
master password and keys never leave the page. Features: sign up / sign in,
2FA login (code or recovery code), 2FA enrolment with QR code, add / edit /
delete / search, CSPRNG password generator, strength meter, show/hide, copy with
**20 s clipboard clearing**, encrypted backups and local CSV import, entry
history with restore, custom fields and encrypted attachments (up to five files
and 2 MiB total per record), and **auto-lock after 5 minutes** (wipes keys and
decrypted entries from the page state). Entry data is rendered with
`textContent` only (no HTML injection), and a strict CSP forbids inline script
and third-party resources. `tests/ui/interop.mjs` runs the real browser crypto
under Node and proves it is byte-compatible with the Python client.

Not yet in the UI (API supports them): change master password, disable 2FA.
`tests/server/test_ui.py` statically checks that every element id used by
`app.js` exists and that no `innerHTML`/`eval` is used.

### Browser autofill extension

`browser_extension/` is a separate unpacked Manifest V3 extension. It asks for
permission to contact one configured server origin, keeps its login token and
vault key only in popup memory, offers exact-origin
personal-vault matches, and fills only after a user clicks a result. It never
submits a site form. The app's WebAuthn passkeys are account second factors and
are managed in the web UI; they require the master password to decrypt the
vault. Set `PWVAULT_WEBAUTHN_RP_ID` and
`PWVAULT_WEBAUTHN_ORIGIN` to the deployment's relying-party hostname and exact
HTTPS origin. Local HTTP is accepted only for localhost development. Passkeys
are an additional login factor; the master password remains necessary to
decrypt the vault.

### Backups, recovery, history and record types

Encrypted backups use a separate passphrase and Argon2id before AES-GCM; CSV
imports are parsed locally, then encrypted before upload. Backup files and
their passphrases should be kept separately. A user-held random recovery key
stores client-encrypted copies of the vault key and account sharing key; it is
shown after setup and is never recoverable from the server. Recovery changes
the master password and still requires TOTP/recovery-code proof when TOTP is
enabled. Password history stores only encrypted prior blobs and keeps the last
10 versions for personal entries. Entry types (login, secure note, payment
card, identity), custom fields and small attachments all remain inside the
encrypted entry blob. Shared vault history is not included yet.

## Roles, admin console and audit log (v0.5)
Roles: `admin` and `employee` (a `team_lead` role arrives with shared vaults).
The first admin is bootstrapped via `PWVAULT_ADMIN_EMAILS`; admins promote others.
**Admins manage accounts but can never read vault contents** (zero-knowledge).

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/users` | accounts, role, locked/disabled, 2FA status, entry count |
| PUT | `/admin/users/{id}/role` | promote / demote |
| POST | `/admin/users/{id}/disable` · `/enable` | offboarding: disabling kills live sessions at once |
| POST | `/admin/users/{id}/unlock` | clear a lockout |
| GET | `/admin/audit` | newest-first audit records (`limit`, `before_seq`) |
| GET | `/admin/audit/verify` | re-check the whole chain, returns the head hash |

**Audit log:** logins, failures, lockouts, 2FA changes, password changes, entry
create/update/delete (ids only) and every admin action, with actor, target, IP
and time. It never stores secrets. Records are chained with an **HMAC** keyed by
a server secret: editing or deleting a record breaks verification, and an
attacker with only database access cannot recompute the chain. Record the
`head_hash` somewhere external periodically to also catch truncation.
Run `scripts/demo_admin.py` for a live tamper-detection demo.
Behind a reverse proxy start uvicorn with `--proxy-headers` so the logged IP is the client's.

## Registration and usability (v1.0)
**Invite-only registration.** With `PWVAULT_REGISTRATION=invite` (set in
`.env.example`; the default `open` is for development) nobody can create an
account without a **single-use code bound to their e-mail**, valid for 7 days.
Admins issue codes in the web UI (Admin > Users > Invite) or via
`POST /admin/invites`; codes are stored hashed and never logged. Addresses in
`PWVAULT_ADMIN_EMAILS` can always register (bootstrap).

**Usability:** show/hide for the master password and entry passwords (hidden by
default), a tip and a "cannot be recovered" confirmation at sign-up, an
invitation field, copy-username and copy-password buttons, an empty state with an
"Add your first password" button, larger touch targets, visible keyboard focus,
mobile-friendly layout. **Clipboard fix:** the 20-second clear now only wipes
the clipboard if it still holds what was copied, so it never erases something
the user copied later (if the browser forbids reading the clipboard it clears
anyway, which is the safer failure).

## Languages: English, Français, العربية (v1.1)
A language selector in the header switches the whole interface, including
**right-to-left layout for Arabic** (passwords, e-mails and key fingerprints stay
left-to-right so they remain readable). The choice is remembered, and the first
visit follows the browser language. Mechanism: the English text is the lookup
key (`static/strings.js`); `i18n.js` translates text and placeholders as they
appear, so screens built by JavaScript are covered automatically. To add a
language, add a dictionary to `strings.js`. **The translations were written
without review by native speakers: have French and Arabic readers check the
banking terms before real use.** Server error messages and the admin audit
entries are still English. Tests check both dictionaries cover the same phrases,
that every visible string in the page has a translation, and run the real engine
in a DOM (`cd tests/ui && npm install` once, then `pytest`).

## Breach check and vault health (v0.6)
`GET /breach/range/{prefix}` is an authenticated **k-anonymity proxy** for Have
I Been Pwned: the client hashes the password (SHA-1, as the HIBP API requires)
and sends only the **first 5 hex characters**; the server forwards just that
prefix (with padding enabled), and the client matches the returned suffixes
locally. HIBP never sees the password, the full hash, the user, or the user's
IP. Disabled unless `PWVAULT_BREACH_CHECK=1`. The web UI adds a *Check
breaches* button in the entry dialog and a **Health** screen that reports
weak, reused and breached passwords; the **Admin** screen (admins only) manages
accounts and shows live audit-chain verification.

## Shared vaults (v0.8)
Teams can share secrets without the server ever being able to read them.
Every user has an **X25519 keypair**: the public key is published, the private
key is stored **sealed under your own enc_key** (so the server cannot use it).
A shared vault has its own random key, sealed separately to each member's
public key (ECIES: ephemeral X25519 + HKDF + AES-256-GCM). Roles:
**viewer** (read) < **editor** (write entries) < **owner** (manage members).

| Method | Path | Purpose |
|---|---|---|
| PUT | `/auth/keypair` | one-time, immutable publication of your public key |
| GET | `/users/lookup?email=` | a colleague's public key (compare **fingerprints** out of band) |
| POST/GET | `/vaults` | create / list your vaults (each with your sealed key) |
| GET/POST | `/vaults/{id}/members` | list / add a member (owner) |
| PUT | `/vaults/{id}/members/{uid}/role` | change role (a vault always keeps one owner) |
| POST | `/vaults/{id}/members/{uid}/remove` | remove a member **and rotate the key** atomically |
| CRUD | `/vaults/{id}/entries[/{eid}]` | shared entries (editors write, viewers read) |

**Removal re-keys the vault**: a new key is generated, every entry and the name
are re-sealed, and only remaining members receive it, in one all-or-nothing
request. A leaver cannot remove themselves (they would mint the new key).
**Offboarding procedure for a bank:** disable the account (admin) *and* have an
owner remove them from each shared vault. Disabling alone does not revoke keys.
Python usage: `RemoteVault.create_shared_vault`, `add_member(vault, email, role,
expected_fingerprint=...)`, `remove_member`, `shared_add_entry`, `shared_list`...
`scripts/demo_sharing.py` runs the whole story live. The **web UI** has a vault switcher (Personal / each shared vault), shared
entries with the same add/edit/delete/health tools, and a **Members** screen:
share by e-mail with optional **fingerprint pinning**, change roles, remove a
member (with the automatic key rotation), delete a vault. Viewers get a
read-only view. Needs a browser with WebCrypto **X25519** (recent Chrome,
Edge, Firefox, Safari; the login shows a clear message otherwise).

### Zero-knowledge key flow
```
master password --Argon2id--> master key --HKDF--> enc_key   (stays on the client)
                                         \-HKDF--> auth_key  (sent to server, which stores Argon2id(auth_key))
enc_key wraps a random vault key; the vault key encrypts every entry (AES-256-GCM, AAD = entry id)
```

## Local CLI design
```
master password --Argon2id(salt)--> KEK --AES-256-GCM--> wraps random VAULT KEY
VAULT KEY --AES-256-GCM(aad = entry id)--> {site, username, password, notes}
```
| Concern | Decision |
|---|---|
| Password -> key | Argon2id, 64 MiB / 3 passes / 4 lanes (OWASP); stored parameters are validated and bounded before derivation |
| Encryption | AES-256-GCM, random 96-bit nonce per encryption |
| Wrong password | Detected by GCM authentication of the wrapped key, no password hash stored |
| Tampering | GCM tag fails; each entry is bound to its row id (AAD), so swapping ciphertexts between rows is detected |
| Metadata | Site names and usernames are encrypted too, only timestamps are plaintext |
| Master password change | Re-wraps the 32-byte vault key with a new salt, entries are not re-encrypted |
| Generator | `secrets` (CSPRNG), guarantees every selected character class |
| Brute force (CLI) | 3 attempts with growing delay, plus Argon2's own cost per guess |

## Known limitations (be upfront about these in your presentation)
* Python cannot reliably wipe secrets from memory; `lock()` is best effort.
* Recovery depends on keeping the generated recovery key. Losing both the master password and recovery key means losing the data.
* The UI strength meter is a simple entropy estimate, not `zxcvbn`. The UI's DOM behaviour (dialogs, timers, buttons) has not been browser-tested end to end: only its crypto and static wiring are covered by tests. The breach proxy was tested against a mocked HIBP, not the live service.
* The sharing screens' DOM behaviour has not been run in a real browser (their crypto is cross-checked against Python in `tests/ui/interop.mjs`); no per-IP rate limiting. Sharing safety depends on users comparing key fingerprints out of band.
* Audit append is a separate transaction after the action (fine for SQLite/single process); production should append in the same transaction on PostgreSQL. Truncating the newest records is only detectable if the head hash was anchored elsewhere.
* Not externally audited.

## Roadmap
2. ~~FastAPI backend: user accounts, TOTP 2FA, REST API~~ (done in v0.3)
3. ~~UI, strength meter, auto-lock, clipboard clearing~~ (done in v0.4)
4. ~~Roles, admin console, tamper-evident audit log~~ (v0.5), ~~HIBP breach check, health + admin screens~~ (v0.6); ~~shared vaults~~ (v0.8); ~~web UI for sharing~~ (v0.9); still to do: browser end-to-end tests
5. ~~Docker / docker-compose, CI~~ (v0.7); still to do: final demo script + slides (threat model is already in `docs/`)
