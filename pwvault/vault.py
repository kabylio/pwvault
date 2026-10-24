"""High-level vault API.

Key hierarchy
-------------
    master password --Argon2id(salt)--> KEK (key-encryption key)
    KEK --AES-GCM--> wraps a random 256-bit VAULT KEY (stored in the header)
    VAULT KEY --AES-GCM--> encrypts every entry (site, username, password, notes)

Why two layers? Changing the master password only re-wraps 32 bytes instead of
re-encrypting every entry, and it is the same pattern real password managers use.

Nothing secret is written to disk in clear text: not the key, not even the
site names. A wrong master password is detected because unwrapping fails the
GCM authentication check.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import DecryptionError, KdfParams
from .storage import Header, Storage

FORMAT_VERSION = 1
MIN_MASTER_LEN = 12
_KEY_AAD = b"pwvault:vault-key:v1"


class VaultError(Exception):
    pass


class InvalidMasterPassword(VaultError):
    pass


class WeakPasswordError(VaultError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_master_password(password: str) -> None:
    if len(password) < MIN_MASTER_LEN:
        raise WeakPasswordError(
            f"Master password must be at least {MIN_MASTER_LEN} characters "
            "(a passphrase of several words works well).")


@dataclass
class Entry:
    id: str
    site: str
    username: str
    password: str
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    version: int = 0          # used by the remote client (optimistic locking)
    type: str = "login"
    fields: dict[str, str] = field(default_factory=dict)
    attachments: list[dict[str, str]] = field(default_factory=list)


def _entry_aad(entry_id: str) -> bytes:
    # Binds each ciphertext to its row id: swapping blobs between rows fails.
    return b"pwvault:entry:v1:" + entry_id.encode()


class Vault:
    def __init__(self, storage: Storage, vault_key: bytes):
        self._storage = storage
        self._key: bytes | None = vault_key

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, path: str | Path, master_password: str,
               kdf: KdfParams = KdfParams()) -> "Vault":
        validate_master_password(master_password)
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"{path} already exists")
        storage = Storage(path)
        storage.open(create=True)

        salt = crypto.random_bytes(crypto.SALT_LEN)
        vault_key = crypto.random_bytes(crypto.KEY_LEN)
        kek = crypto.derive_key(master_password, salt, kdf)
        storage.write_header(Header(
            version=FORMAT_VERSION, salt=salt, time_cost=kdf.time_cost,
            memory_cost_kib=kdf.memory_cost_kib, parallelism=kdf.parallelism,
            wrapped_key=crypto.encrypt(kek, vault_key, _KEY_AAD)))
        return cls(storage, vault_key)

    @classmethod
    def open(cls, path: str | Path, master_password: str) -> "Vault":
        storage = Storage(path)
        storage.open(create=False)
        try:
            vault_key = cls._unwrap(storage, master_password)
        except Exception:
            storage.close()
            raise
        return cls(storage, vault_key)

    @staticmethod
    def _unwrap(storage: Storage, master_password: str) -> bytes:
        header = storage.read_header()
        if header is None:
            raise VaultError("not a valid vault file (missing header)")
        if header.version != FORMAT_VERSION:
            raise VaultError(f"unsupported vault version {header.version}")
        params = KdfParams(header.time_cost, header.memory_cost_kib,
                           header.parallelism)
        kek = crypto.derive_key(master_password, header.salt, params)
        try:
            return crypto.decrypt(kek, header.wrapped_key, _KEY_AAD)
        except DecryptionError:
            raise InvalidMasterPassword("wrong master password") from None

    def lock(self) -> None:
        """Forget the key and close the file. (Python can't guarantee memory
        wiping; this is best effort and documented as a known limitation.)"""
        self._key = None
        self._storage.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc) -> None:
        self.lock()

    @property
    def is_locked(self) -> bool:
        return self._key is None

    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultError("vault is locked")
        return self._key

    # --------------------------------------------------------------- entries
    def _seal(self, e: Entry) -> bytes:
        payload = json.dumps(
            {"site": e.site, "username": e.username,
             "password": e.password, "notes": e.notes, "type": e.type,
             "fields": e.fields, "attachments": e.attachments}).encode()
        return crypto.encrypt(self._require_key(), payload, _entry_aad(e.id))

    def _open(self, row) -> Entry:
        entry_id, blob, created, updated = row
        try:
            data = json.loads(crypto.decrypt(
                self._require_key(), blob, _entry_aad(entry_id)))
        except DecryptionError:
            raise VaultError(
                f"entry {entry_id} is corrupted or has been tampered with"
            ) from None
        return Entry(id=entry_id, created_at=created, updated_at=updated, **data)

    def add_entry(self, site: str, username: str, password: str,
                  notes: str = "") -> str:
        if not site.strip():
            raise ValueError("site name is required")
        entry = Entry(id=str(uuid.uuid4()), site=site.strip(),
                      username=username, password=password, notes=notes)
        self._storage.insert_entry(entry.id, self._seal(entry), _now())
        return entry.id

    def get_entry(self, entry_id: str) -> Entry:
        row = self._storage.get_entry(entry_id)
        if row is None:
            raise KeyError(entry_id)
        return self._open(row)

    def list_entries(self) -> list[Entry]:
        entries = [self._open(r) for r in self._storage.all_entries()]
        return sorted(entries, key=lambda e: e.site.lower())

    def find(self, query: str) -> list[Entry]:
        q = query.lower().strip()
        return [e for e in self.list_entries()
                if q in e.site.lower() or q in e.username.lower()]

    def update_entry(self, entry_id: str, **fields: str) -> None:
        allowed = {"site", "username", "password", "notes"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}")
        entry = self.get_entry(entry_id)
        for name, value in fields.items():
            setattr(entry, name, value)
        self._storage.update_entry(entry_id, self._seal(entry), _now())

    def delete_entry(self, entry_id: str) -> bool:
        return self._storage.delete_entry(entry_id)

    # -------------------------------------------------------- master password
    def change_master_password(self, old_password: str, new_password: str,
                               kdf: KdfParams | None = None) -> None:
        """Re-wrap the vault key under a new master password (new random salt).
        Entries are untouched because they are encrypted with the vault key."""
        validate_master_password(new_password)
        vault_key = self._unwrap(self._storage, old_password)  # re-verify old
        header = self._storage.read_header()
        params = kdf or KdfParams(header.time_cost, header.memory_cost_kib,
                                  header.parallelism)
        salt = crypto.random_bytes(crypto.SALT_LEN)
        kek = crypto.derive_key(new_password, salt, params)
        self._storage.write_header(Header(
            version=FORMAT_VERSION, salt=salt, time_cost=params.time_cost,
            memory_cost_kib=params.memory_cost_kib,
            parallelism=params.parallelism,
            wrapped_key=crypto.encrypt(kek, vault_key, _KEY_AAD)))
