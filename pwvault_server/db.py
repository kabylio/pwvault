"""Database models. The server only stores ciphertext and hashes."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, LargeBinary,
                        String, Text, create_engine, inspect, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    # Argon2id hash OF the client's auth key (the master password never arrives)
    auth_hash: Mapped[str] = mapped_column(String(255))
    # Public KDF inputs the client needs before it can log in
    salt: Mapped[bytes] = mapped_column(LargeBinary(16))
    kdf_time_cost: Mapped[int] = mapped_column(Integer)
    kdf_memory_kib: Mapped[int] = mapped_column(Integer)
    kdf_parallelism: Mapped[int] = mapped_column(Integer)
    # Vault key encrypted by the client; the server cannot open it
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    role: Mapped[str] = mapped_column(String(16), default="employee", server_default="employee")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)           # X25519
    wrapped_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # under enc_key
    recovery_salt: Mapped[bytes | None] = mapped_column(LargeBinary(16), nullable=True)
    recovery_auth_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recovery_wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    recovery_wrapped_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    credential_id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(80), default="Passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PasskeyChallenge(Base):
    __tablename__ = "passkey_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    purpose: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary)        # opaque ciphertext
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class EntryRevision(Base):
    __tablename__ = "entry_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(36), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)


def make_engine(url: str):
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    return create_engine(url, **kwargs)


class AuditRecord(Base):
    """Append-only, HMAC-chained log. Every column below is covered by `hash`."""
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str] = mapped_column(Text)            # canonical JSON, no secrets
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


def migrate(engine) -> None:
    """Add columns introduced after v0.3 to an existing database."""
    cols = {c["name"] for c in inspect(engine).get_columns("users")}
    blob = "BYTEA" if engine.dialect.name == "postgresql" else "BLOB"
    wanted = {"role": "VARCHAR(16) NOT NULL DEFAULT 'employee'",
              "disabled": "BOOLEAN NOT NULL DEFAULT FALSE",
              "public_key": blob, "wrapped_private_key": blob,
              "recovery_salt": blob, "recovery_auth_hash": "VARCHAR(255)",
              "recovery_wrapped_key": blob, "recovery_wrapped_private_key": blob}
    for name, ddl in wanted.items():
        if name not in cols:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))


class SharedVault(Base):
    __tablename__ = "shared_vaults"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name_blob: Mapped[bytes] = mapped_column(LargeBinary)     # name encrypted with the vault key
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class VaultMember(Base):
    __tablename__ = "vault_members"

    vault_id: Mapped[str] = mapped_column(ForeignKey("shared_vaults.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(String(8))              # owner | editor | viewer
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)   # vault key sealed to THIS user's public key
    created_at: Mapped[datetime] = mapped_column(DateTime)


class SharedEntry(Base):
    __tablename__ = "shared_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vault_id: Mapped[str] = mapped_column(ForeignKey("shared_vaults.id"), index=True)
    created_by: Mapped[str] = mapped_column(String(36))
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class Invite(Base):
    """Single-use registration invitation, bound to one e-mail. Only a hash is stored."""
    __tablename__ = "invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(254), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(36))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
