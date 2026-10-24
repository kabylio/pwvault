# Threat model (v0.8)

## What we protect
1. **Vault contents**: sites, usernames, passwords, notes.
2. **Master password** and the keys derived from it.
3. **Account access** (login, 2FA).

## Trust assumptions
* The **client device** is trusted while the vault is unlocked.
* The **server is NOT trusted with secrets**. It must be able to be breached
  without exposing vault contents (zero-knowledge design).
* TLS terminates in front of the API (required in production).

## Attackers and what happens
| # | Attacker / event | Outcome | Mitigation |
|---|---|---|---|
| 1 | **Database leak** (SQL injection, stolen backup) | Attacker gets ciphertext, KDF salts, hashes | Entries are AES-256-GCM under a key the server never has. Login material is `Argon2id(auth_key)`, so a leaked hash can't be replayed as a login. Offline guessing must beat Argon2id (64 MiB) per guess. TOTP secrets are encrypted with a key held outside the DB. |
| 2 | **Malicious / compromised server operator** | Can delete or withhold data; cannot read it | Zero-knowledge. Tampering is detected: every blob is authenticated and bound to its entry id (AAD). *Not covered:* a malicious server serving a modified client, or rolling back to an older valid blob. |
| 3 | **Online password guessing** | Slowed and stopped | Account lockout (5 failures -> 15 min), constant-work login for unknown users, Argon2 cost. *Gap:* no per-IP rate limit yet; lockout can be abused to lock a victim out (DoS). |
| 4 | **Stolen access token** | Limited blast radius | 15-minute lifetime, revoked on password change (`token_version`). Setting up or disabling 2FA requires the master-password proof; password changes also require a second factor when 2FA is enabled. |
| 5 | **Phished/leaked password** | Login still blocked | TOTP 2FA; codes are single-use (no replay) and +-30 s tolerant; 8 hashed single-use recovery codes. |
| 6 | **Account enumeration** | Mitigated | `/prelogin` returns a stable fake salt for unknown e-mails; identical error and timing for unknown user / wrong password. *Gap:* registration says "email exists" (409) and a locked account says 429. |
| 7 | **Cross-user access (IDOR)** | Blocked | Every query is filtered by the authenticated user id; foreign ids return 404; tested. |
| 8 | **JWT forgery** | Blocked | HS256 pinned (rejects `alg: none`), secret from environment, min 32 chars. |
| 9 | **Concurrent edits** | No lost updates | Optimistic locking (`version`) enforced in a single atomic UPDATE. |
| 10 | **Weak client KDF chosen** | Rejected | Server enforces OWASP minimum Argon2id parameters at registration. |

| 11 | **Insider / admin abuse** | Limited, visible | Admins cannot decrypt vaults. Every admin action is audited with actor, target, IP. Admins can't demote or disable themselves. |
| 12 | **Log tampering** (hiding a breach) | Detected | HMAC-chained audit log; edits, deletions and reordering fail `/admin/audit/verify`. Forging needs the server key, which is not in the database. *Gap:* removing the newest records is undetectable unless the head hash was recorded externally. |
| 13 | **Departed employee** | Access ends at once | Disabling an account bumps `token_version`, killing all live sessions; login is refused. |

| 14 | **Reusing a breached password** | Warned | Optional HIBP check. Only a 5-char hash prefix leaves the system, relayed by the server so HIBP learns neither the user nor their IP. A malicious server could still *log* prefixes (it already knows less than the vault holds). |
| 15 | **Server swaps a public key** when you share (the classic zero-knowledge weakness) | Detectable | `add_member(..., expected_fingerprint=...)` refuses a mismatching key; your own key is checked against your private key at every login. *Gap:* fingerprints must be compared out of band (phone, in person); there is no key-transparency log. |
| 16 | **Removed member keeps reading** | Blocked going forward | Removal atomically rotates the vault key and re-seals every entry; only remaining members get the new key. A leaver cannot trigger their own removal. *Limit:* they keep anything they already saw or copied. |
| 17 | **Viewer writes / editor manages members** | Blocked | Server-enforced roles, tested. *Limit:* roles are access control, not cryptography: a viewer holds the key, so a colluding server could accept forged writes. |
| 18 | **Ciphertext replayed in another context** | Detected | Every sealed blob is bound (AAD) to vault, entry/member and key version. |

## Out of scope / known gaps
* Malware on the user's device, shoulder surfing, keyloggers.
* Memory scraping of the client (Python cannot reliably zero secrets).
* Server-side rollback attacks; no signed vault history yet.
* Per-IP rate limiting, CAPTCHA, e-mail verification. (Open sign-up is closed by invite-only mode, but invitations are only as private as the channel the admin uses to send them.)
* **Offboarding:** disabling an account stops it logging in but does NOT revoke vault keys it already holds. Owners must also remove the person from each shared vault (which rotates the key).
* `/users/lookup` lets any signed-in user check whether a colleague's address exists.
* E-mail verification (an attacker could pre-register the admin e-mail before the real admin does, so register the admin account immediately at deployment).
* No independent security audit or penetration test.

## Planned next
Per-IP rate limiting, web UI for sharing, key-transparency / signed key directory,
rotating refresh tokens, off-box anchoring of the audit head.
