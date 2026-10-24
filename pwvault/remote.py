"""Client for the pwvault server. ALL cryptography happens here.

    master password --Argon2id--> master key
    master key --HKDF--> enc_key   (never leaves this process)
    master key --HKDF--> auth_key  (sent to the server as the login proof)

The server learns the auth_key but cannot derive enc_key from it (HKDF with
different labels), so it can never decrypt the vault.
"""
from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import breach, crypto, sharing
from .crypto import DecryptionError, KdfParams
from .vault import Entry, VaultError, _entry_aad, validate_master_password

_WRAP_AAD = b"pwvault:remote-vault-key:v1"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _hkdf(master_key: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=label).derive(master_key)


def derive_keys(password: str, salt: bytes, kdf: KdfParams) -> tuple[bytes, bytes]:
    """Return (enc_key, auth_key)."""
    master = crypto.derive_key(password, salt, kdf)
    return _hkdf(master, b"pwvault:v3:enc"), _hkdf(master, b"pwvault:v3:auth")


class RemoteError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class OtpRequired(RemoteError):
    """Server wants a TOTP code (or recovery code) to finish logging in."""


def _kdf_json(k: KdfParams) -> dict:
    return {"time_cost": k.time_cost, "memory_cost_kib": k.memory_cost_kib,
            "parallelism": k.parallelism}


def _call(http: httpx.Client, method: str, path: str, token: str | None = None,
          **kwargs):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = http.request(method, path, headers=headers, **kwargs)
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        if resp.status_code == 401 and detail == "otp_required":
            raise OtpRequired(401, detail)
        raise RemoteError(resp.status_code, str(detail))
    if resp.headers.get("content-type", "").startswith("text/plain"):
        return resp.text
    return resp.json() if resp.content else None


class RemoteVault:
    def __init__(self, http, email, salt, kdf, vault_key, token):
        self._http, self.email = http, email
        self._salt, self._kdf = salt, kdf
        self._vault_key: bytes | None = vault_key
        self._token: str | None = token
        self._priv: bytes | None = None      # X25519 private key (in memory only)
        self._pub: bytes | None = None
        self._uid: str | None = None

    # ------------------------------------------------------------- account
    @staticmethod
    def register(http: httpx.Client, email: str, master_password: str,
                 kdf: KdfParams = KdfParams(), invite_code: str | None = None) -> None:
        validate_master_password(master_password)
        salt = crypto.random_bytes(crypto.SALT_LEN)
        enc_key, auth_key = derive_keys(master_password, salt, kdf)
        vault_key = crypto.random_bytes(crypto.KEY_LEN)
        extra = {"invite_code": invite_code} if invite_code else {}
        _call(http, "POST", "/auth/register", json={**extra,
            "email": email, "auth_key": _b64e(auth_key), "salt": _b64e(salt),
            "kdf": _kdf_json(kdf),
            "wrapped_key": _b64e(crypto.encrypt(enc_key, vault_key, _WRAP_AAD))})

    @classmethod
    def login(cls, http: httpx.Client, email: str, master_password: str,
              otp: str | None = None, recovery_code: str | None = None
              ) -> "RemoteVault":
        pre = _call(http, "POST", "/auth/prelogin", json={"email": email})
        salt = _b64d(pre["salt"])
        kdf = KdfParams(pre["kdf"]["time_cost"], pre["kdf"]["memory_cost_kib"],
                        pre["kdf"]["parallelism"])
        enc_key, auth_key = derive_keys(master_password, salt, kdf)
        body = {"email": email, "auth_key": _b64e(auth_key)}
        if otp:
            body["otp"] = otp
        if recovery_code:
            body["recovery_code"] = recovery_code
        data = _call(http, "POST", "/auth/login", json=body)
        try:
            vault_key = crypto.decrypt(enc_key, _b64d(data["wrapped_key"]), _WRAP_AAD)
        except DecryptionError:
            raise VaultError("server returned a vault key that cannot be "
                             "decrypted") from None
        vault = cls(http, email, salt, kdf, vault_key, data["access_token"])
        vault._init_keypair(enc_key, data)
        return vault

    def _init_keypair(self, enc_key: bytes, data: dict) -> None:
        self._uid = self.me()["id"]
        if data.get("wrapped_private_key"):
            self._priv = crypto.decrypt(enc_key, _b64d(data["wrapped_private_key"]), sharing.PRIV_AAD)
            self._pub = sharing.public_from_private(self._priv)
            if self._pub != _b64d(data["public_key"]):     # a swapped public key is caught here
                raise VaultError("the server's public key for you does not match your private key")
        else:                                              # first login after sharing was introduced
            self._priv, self._pub = sharing.generate_keypair()
            self._req("PUT", "/auth/keypair", json={"public_key": _b64e(self._pub),
                "wrapped_private_key": _b64e(crypto.encrypt(enc_key, self._priv, sharing.PRIV_AAD))})

    def my_fingerprint(self) -> str:
        return sharing.fingerprint(self._pub)

    def logout(self) -> None:
        """Forget keys and token locally (tokens also expire server-side)."""
        self._priv = self._pub = None
        self._vault_key = None
        self._token = None

    def _req(self, method: str, path: str, **kw):
        if self._token is None or self._vault_key is None:
            raise VaultError("session is closed")
        return _call(self._http, method, path, self._token, **kw)

    def me(self) -> dict:
        return self._req("GET", "/auth/me")

    def change_master_password(self, old_password: str, new_password: str,
                               kdf: KdfParams | None = None,
                               otp: str | None = None,
                               recovery_code: str | None = None,
                               passkey_challenge_id: str | None = None,
                               passkey_assertion: dict[str, Any] | None = None) -> None:
        validate_master_password(new_password)
        _, old_auth = derive_keys(old_password, self._salt, self._kdf)
        kdf = kdf or self._kdf
        salt = crypto.random_bytes(crypto.SALT_LEN)
        enc_key, auth_key = derive_keys(new_password, salt, kdf)
        body = {
            "current_auth_key": _b64e(old_auth), "new_auth_key": _b64e(auth_key),
            "new_salt": _b64e(salt), "new_kdf": _kdf_json(kdf),
            "new_wrapped_key": _b64e(
                crypto.encrypt(enc_key, self._vault_key, _WRAP_AAD)),
            "new_wrapped_private_key": _b64e(
                crypto.encrypt(enc_key, self._priv, sharing.PRIV_AAD))}
        if otp:
            body["otp"] = otp
        if recovery_code:
            body["recovery_code"] = recovery_code
        if passkey_challenge_id and passkey_assertion:
            body["passkey_challenge_id"] = passkey_challenge_id
            body["passkey_assertion"] = passkey_assertion
        data = self._req("POST", "/auth/change-password", json=body)
        self._salt, self._kdf, self._token = salt, kdf, data["access_token"]

    # ----------------------------------------------------------------- 2FA
    def setup_2fa(self, master_password: str) -> tuple[str, str]:
        _, auth_key = derive_keys(master_password, self._salt, self._kdf)
        data = self._req("POST", "/auth/2fa/setup", json={"auth_key": _b64e(auth_key)})
        return data["secret"], data["otpauth_uri"]

    def enable_2fa(self, code: str) -> list[str]:
        return self._req("POST", "/auth/2fa/enable", json={"code": code})["recovery_codes"]

    def disable_2fa(self, master_password: str, otp: str | None = None,
                    recovery_code: str | None = None) -> None:
        _, auth_key = derive_keys(master_password, self._salt, self._kdf)
        body = {"auth_key": _b64e(auth_key)}
        if otp:
            body["otp"] = otp
        if recovery_code:
            body["recovery_code"] = recovery_code
        self._req("POST", "/auth/2fa/disable", json=body)

    # ------------------------------------------------------------- entries
    def _seal(self, e: Entry) -> str:
        payload = json.dumps({"site": e.site, "username": e.username,
                              "password": e.password, "notes": e.notes, "type": e.type,
                              "fields": e.fields, "attachments": e.attachments}).encode()
        return _b64e(crypto.encrypt(self._vault_key, payload, _entry_aad(e.id)))

    def _open(self, row: dict) -> Entry:
        try:
            data = json.loads(crypto.decrypt(
                self._vault_key, _b64d(row["blob"]), _entry_aad(row["id"])))
        except DecryptionError:
            raise VaultError(f"entry {row['id']} is corrupted or has been "
                             "tampered with") from None
        e = Entry(id=row["id"], created_at=row["created_at"],
                  updated_at=row["updated_at"], **data)
        e.version = row["version"]          # remembered for safe updates
        return e

    def add_entry(self, site: str, username: str, password: str,
                  notes: str = "") -> str:
        if not site.strip():
            raise ValueError("site name is required")
        e = Entry(id=str(uuid.uuid4()), site=site.strip(), username=username,
                  password=password, notes=notes)
        self._req("POST", "/entries", json={"id": e.id, "blob": self._seal(e)})
        return e.id

    def get_entry(self, entry_id: str) -> Entry:
        return self._open(self._req("GET", f"/entries/{entry_id}"))

    def list_entries(self) -> list[Entry]:
        rows = self._req("GET", "/entries")
        return sorted((self._open(r) for r in rows), key=lambda e: e.site.lower())

    def find(self, query: str) -> list[Entry]:
        q = query.lower().strip()
        return [e for e in self.list_entries()
                if q in e.site.lower() or q in e.username.lower()]

    def update_entry(self, entry_id: str, **fields: Any) -> None:
        allowed = {"site", "username", "password", "notes", "type", "fields", "attachments"}
        if set(fields) - allowed:
            raise ValueError("unknown field(s)")
        e = self.get_entry(entry_id)
        for k, v in fields.items():
            setattr(e, k, v)
        self._req("PUT", f"/entries/{entry_id}",
                  json={"blob": self._seal(e), "version": e.version})

    def delete_entry(self, entry_id: str) -> None:
        self._req("DELETE", f"/entries/{entry_id}")

    # --------------------------------------------------------------- admin
    def admin_users(self) -> list[dict]:
        return self._req("GET", "/admin/users")

    def admin_set_role(self, user_id: str, role: str) -> None:
        self._req("PUT", f"/admin/users/{user_id}/role", json={"role": role})

    def admin_disable(self, user_id: str) -> None:
        self._req("POST", f"/admin/users/{user_id}/disable")

    def admin_enable(self, user_id: str) -> None:
        self._req("POST", f"/admin/users/{user_id}/enable")

    def admin_unlock(self, user_id: str) -> None:
        self._req("POST", f"/admin/users/{user_id}/unlock")

    def audit(self, limit: int = 100, before_seq: int | None = None) -> list[dict]:
        params = {"limit": limit, **({"before_seq": before_seq} if before_seq else {})}
        return self._req("GET", "/admin/audit", params=params)

    def audit_verify(self) -> dict:
        return self._req("GET", "/admin/audit/verify")

    # -------------------------------------------------------- breach check
    def breach_count(self, password: str) -> int:
        """How many known breaches contain this password (0 = none found).
        Only a 5-char hash prefix is sent, via the server's k-anonymity proxy."""
        prefix, suffix = breach.split_hash(password)
        return breach.count_in_range(self._req("GET", f"/breach/range/{prefix}"), suffix)

    # ------------------------------------------------------- shared vaults
    def _vault_row(self, vault_id: str) -> dict:
        for row in self._req("GET", "/vaults"):
            if row["id"] == vault_id:
                return row
        raise RemoteError(404, "Vault not found")

    def _shared_key(self, row: dict) -> bytes:
        try:
            return sharing.unwrap(self._priv, _b64d(row["wrapped_key"]),
                                  sharing.key_aad(row["id"], self._uid, row["key_version"]))
        except DecryptionError:
            raise VaultError("cannot open this vault's key (wrong member, or tampered)") from None

    def create_shared_vault(self, name: str) -> str:
        vid, key = str(uuid.uuid4()), crypto.random_bytes(crypto.KEY_LEN)
        self._req("POST", "/vaults", json={
            "id": vid,
            "name_blob": _b64e(crypto.encrypt(key, name.encode(), sharing.name_aad(vid, 1))),
            "wrapped_key": _b64e(sharing.wrap_for(self._pub, key, sharing.key_aad(vid, self._uid, 1)))})
        return vid

    def list_shared_vaults(self) -> list[dict]:
        out = []
        for row in self._req("GET", "/vaults"):
            key = self._shared_key(row)
            name = crypto.decrypt(key, _b64d(row["name_blob"]),
                                  sharing.name_aad(row["id"], row["key_version"])).decode()
            out.append({"id": row["id"], "name": name, "role": row["role"],
                        "key_version": row["key_version"]})
        return out

    def shared_members(self, vault_id: str) -> list[dict]:
        return [{**m, "fingerprint": sharing.fingerprint(_b64d(m["public_key"]))}
                for m in self._req("GET", f"/vaults/{vault_id}/members")]

    def add_member(self, vault_id: str, email: str, role: str = "viewer",
                   expected_fingerprint: str | None = None) -> str:
        """Share the vault with a colleague. Pass the fingerprint they read to
        you out of band: if the server hands back a different key, we refuse."""
        found = self._req("GET", "/users/lookup", params={"email": email})
        pub = _b64d(found["public_key"])
        fp = sharing.fingerprint(pub)
        if expected_fingerprint and expected_fingerprint.replace(" ", "").upper() != fp.replace(" ", ""):
            raise VaultError(f"fingerprint mismatch for {email}: expected {expected_fingerprint}, "
                             f"server returned {fp}. Not sharing.")
        row = self._vault_row(vault_id)
        key = self._shared_key(row)
        self._req("POST", f"/vaults/{vault_id}/members", json={
            "user_id": found["id"], "role": role, "key_version": row["key_version"],
            "wrapped_key": _b64e(sharing.wrap_for(
                pub, key, sharing.key_aad(vault_id, found["id"], row["key_version"])))})
        return fp

    def set_member_role(self, vault_id: str, user_id: str, role: str) -> None:
        self._req("PUT", f"/vaults/{vault_id}/members/{user_id}/role", json={"role": role})

    def remove_member(self, vault_id: str, user_id: str) -> None:
        """Remove a member AND rotate the vault key: a new key is generated,
        every entry and the name are re-sealed, and only the remaining members
        receive it. All in one atomic request."""
        row = self._vault_row(vault_id)
        old_key, new_key = self._shared_key(row), crypto.random_bytes(crypto.KEY_LEN)
        old_v, new_v = row["key_version"], row["key_version"] + 1
        members = [m for m in self._req("GET", f"/vaults/{vault_id}/members") if m["user_id"] != user_id]
        entries = []
        for e in self._req("GET", f"/vaults/{vault_id}/entries"):
            plain = crypto.decrypt(old_key, _b64d(e["blob"]), sharing.entry_aad(vault_id, e["id"], old_v))
            entries.append({"id": e["id"], "version": e["version"], "blob": _b64e(
                crypto.encrypt(new_key, plain, sharing.entry_aad(vault_id, e["id"], new_v)))})
        name = crypto.decrypt(old_key, _b64d(row["name_blob"]), sharing.name_aad(vault_id, old_v))
        self._req("POST", f"/vaults/{vault_id}/members/{user_id}/remove", json={
            "key_version": new_v,
            "name_blob": _b64e(crypto.encrypt(new_key, name, sharing.name_aad(vault_id, new_v))),
            "member_keys": {m["user_id"]: _b64e(sharing.wrap_for(
                _b64d(m["public_key"]), new_key, sharing.key_aad(vault_id, m["user_id"], new_v)))
                for m in members},
            "entries": entries})

    def delete_shared_vault(self, vault_id: str) -> None:
        self._req("DELETE", f"/vaults/{vault_id}")

    def _seal_shared(self, key: bytes, vault_id: str, e: Entry, kv: int) -> str:
        payload = json.dumps({"site": e.site, "username": e.username,
                              "password": e.password, "notes": e.notes}).encode()
        return _b64e(crypto.encrypt(key, payload, sharing.entry_aad(vault_id, e.id, kv)))

    def _open_shared(self, key: bytes, vault_id: str, row: dict) -> Entry:
        try:
            data = json.loads(crypto.decrypt(key, _b64d(row["blob"]),
                                             sharing.entry_aad(vault_id, row["id"], row["key_version"])))
        except DecryptionError:
            raise VaultError(f"shared entry {row['id']} is corrupted or has been tampered with") from None
        e = Entry(id=row["id"], created_at=row["created_at"], updated_at=row["updated_at"], **data)
        e.version = row["version"]
        return e

    def shared_add_entry(self, vault_id: str, site: str, username: str, password: str,
                         notes: str = "") -> str:
        row = self._vault_row(vault_id)
        e = Entry(id=str(uuid.uuid4()), site=site.strip(), username=username, password=password, notes=notes)
        self._req("POST", f"/vaults/{vault_id}/entries", json={
            "id": e.id, "key_version": row["key_version"],
            "blob": self._seal_shared(self._shared_key(row), vault_id, e, row["key_version"])})
        return e.id

    def shared_get(self, vault_id: str, entry_id: str) -> Entry:
        key = self._shared_key(self._vault_row(vault_id))
        return self._open_shared(key, vault_id, self._req("GET", f"/vaults/{vault_id}/entries/{entry_id}"))

    def shared_list(self, vault_id: str) -> list[Entry]:
        key = self._shared_key(self._vault_row(vault_id))
        rows = self._req("GET", f"/vaults/{vault_id}/entries")
        return sorted((self._open_shared(key, vault_id, r) for r in rows), key=lambda e: e.site.lower())

    def shared_update(self, vault_id: str, entry_id: str, **fields: str) -> None:
        if set(fields) - {"site", "username", "password", "notes"}:
            raise ValueError("unknown field(s)")
        row = self._vault_row(vault_id)
        key = self._shared_key(row)
        e = self._open_shared(key, vault_id, self._req("GET", f"/vaults/{vault_id}/entries/{entry_id}"))
        for k, v in fields.items():
            setattr(e, k, v)
        self._req("PUT", f"/vaults/{vault_id}/entries/{entry_id}", json={
            "version": e.version, "key_version": row["key_version"],
            "blob": self._seal_shared(key, vault_id, e, row["key_version"])})

    def shared_delete(self, vault_id: str, entry_id: str) -> None:
        self._req("DELETE", f"/vaults/{vault_id}/entries/{entry_id}")

    def admin_invite(self, email: str) -> dict:
        return self._req("POST", "/admin/invites", json={"email": email})
