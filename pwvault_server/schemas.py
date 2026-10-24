"""Request/response models. Everything is validated before it reaches logic."""
from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, StringConstraints, model_validator


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64_check(exact: int | None = None, min_len: int = 1):
    def check(value: str) -> str:
        try:
            raw = b64d(value)
        except Exception:
            raise ValueError("must be valid base64") from None
        if exact is not None and len(raw) != exact:
            raise ValueError(f"must decode to exactly {exact} bytes")
        if len(raw) < min_len:
            raise ValueError(f"must decode to at least {min_len} bytes")
        return value
    return check


Key32 = Annotated[str, StringConstraints(max_length=64), AfterValidator(_b64_check(32))]
Salt16 = Annotated[str, StringConstraints(max_length=32), AfterValidator(_b64_check(16))]
# nonce(12) + GCM tag(16) is the smallest valid ciphertext; cap ~64 KiB
Blob = Annotated[str, StringConstraints(max_length=90_000),
                 AfterValidator(_b64_check(None, 28))]
# Up to 2 MiB encrypted attachment payload plus JSON/base64 framing.
LargeBlob = Annotated[str, StringConstraints(max_length=5_600_000),
                      AfterValidator(_b64_check(None, 28))]
Email = Annotated[str, StringConstraints(
    strip_whitespace=True, to_lower=True, max_length=254,
    pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
Otp = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]
RecoveryCodeStr = Annotated[str, StringConstraints(max_length=32)]


class Kdf(BaseModel):
    time_cost: int = Field(ge=1, le=10)
    memory_cost_kib: int = Field(ge=8, le=524_288)
    parallelism: int = Field(ge=1, le=16)

    @model_validator(mode="after")
    def memory_matches_parallelism(self):
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValueError("memory_cost_kib must be at least 8 times parallelism")
        return self


# ------------------------------------------------------------------- auth
class RegisterIn(BaseModel):
    email: Email
    auth_key: Key32
    salt: Salt16
    kdf: Kdf
    wrapped_key: Blob
    invite_code: str | None = Field(default=None, max_length=64)


class PreloginIn(BaseModel):
    email: Email


class PreloginOut(BaseModel):
    salt: str
    kdf: Kdf


class LoginIn(BaseModel):
    email: Email
    auth_key: Key32
    otp: Otp | None = None
    recovery_code: RecoveryCodeStr | None = None
    passkey_challenge_id: str | None = Field(default=None, max_length=36)
    passkey_assertion: dict | None = None

    @model_validator(mode="after")
    def one_second_factor(self):
        if self.passkey_challenge_id is not None and self.passkey_assertion is None:
            raise ValueError("passkey assertion is required")
        if self.passkey_assertion is not None and (self.passkey_challenge_id is None or self.otp or self.recovery_code):
            raise ValueError("provide exactly one second factor")
        if self.otp and self.recovery_code:
            raise ValueError("provide exactly one second factor")
        return self


class PasskeyAuthOptionsIn(BaseModel):
    email: Email
    auth_key: Key32


class SecondFactorIn(BaseModel):
    otp: Otp | None = None
    recovery_code: RecoveryCodeStr | None = None
    passkey_challenge_id: str | None = Field(default=None, max_length=36)
    passkey_assertion: dict | None = None

    @model_validator(mode="after")
    def one_second_factor(self):
        if self.passkey_challenge_id is not None and self.passkey_assertion is None:
            raise ValueError("passkey assertion is required")
        if self.passkey_assertion is not None and (self.passkey_challenge_id is None or self.otp or self.recovery_code):
            raise ValueError("provide exactly one second factor")
        if self.otp and self.recovery_code:
            raise ValueError("provide exactly one second factor")
        return self


class PasskeyRegistrationOptionsIn(SecondFactorIn):
    auth_key: Key32


class PasskeyRemovalIn(SecondFactorIn):
    auth_key: Key32


class PasskeyRegistrationIn(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict
    name: str = Field(default="Passkey", max_length=80)


class RecoverySetupIn(SecondFactorIn):
    auth_key: Key32
    recovery_auth_key: Key32
    recovery_salt: Salt16
    recovery_wrapped_key: Blob
    recovery_wrapped_private_key: Blob | None = None
class RecoveryOptionsIn(BaseModel):
    email: Email


class RecoveryOptionsOut(BaseModel):
    recovery_salt: str
    recovery_wrapped_key: str
    recovery_wrapped_private_key: str | None = None


class RecoveryCompleteIn(BaseModel):
    email: Email
    recovery_auth_key: Key32
    new_auth_key: Key32
    new_salt: Salt16
    new_kdf: Kdf
    new_wrapped_key: Blob
    new_wrapped_private_key: Blob | None = None
    otp: Otp | None = None
    recovery_code: RecoveryCodeStr | None = None

    @model_validator(mode="after")
    def one_second_factor(self):
        if self.otp and self.recovery_code:
            raise ValueError("provide exactly one second factor")
        return self


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    wrapped_key: str
    public_key: str | None = None
    wrapped_private_key: str | None = None


class MeOut(BaseModel):
    id: str
    email: str
    role: str
    totp_enabled: bool
    created_at: datetime
    public_key: str | None = None


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TotpSetupIn(SecondFactorIn):
    auth_key: Key32


class TotpEnableIn(BaseModel):
    code: Otp


class TotpEnableOut(BaseModel):
    recovery_codes: list[str]


class TotpDisableIn(SecondFactorIn):
    auth_key: Key32


class ChangePasswordIn(BaseModel):
    current_auth_key: Key32
    new_auth_key: Key32
    new_salt: Salt16
    new_kdf: Kdf
    new_wrapped_key: Blob
    new_wrapped_private_key: Blob | None = None   # required once a keypair exists
    otp: Otp | None = None
    recovery_code: RecoveryCodeStr | None = None
    passkey_challenge_id: str | None = Field(default=None, max_length=36)
    passkey_assertion: dict | None = None

    @model_validator(mode="after")
    def one_second_factor(self):
        if self.passkey_challenge_id is not None and self.passkey_assertion is None:
            raise ValueError("passkey assertion is required")
        if self.passkey_assertion is not None and (self.passkey_challenge_id is None or self.otp or self.recovery_code):
            raise ValueError("provide exactly one second factor")
        if self.otp and self.recovery_code:
            raise ValueError("provide exactly one second factor")
        return self


# ---------------------------------------------------------------- entries
class EntryCreate(BaseModel):
    id: uuid.UUID               # generated by the client (used as AAD)
    blob: LargeBlob


class EntryUpdate(BaseModel):
    blob: LargeBlob
    version: int = Field(ge=1)  # optimistic concurrency: version you last saw


class EntryOut(BaseModel):
    id: str
    blob: str
    version: int
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------------------ admin
from typing import Literal  # noqa: E402


class RoleIn(BaseModel):
    role: Literal["admin", "employee"]


class AdminUserOut(BaseModel):
    id: str
    email: str
    role: str
    disabled: bool
    locked: bool
    totp_enabled: bool
    entry_count: int          # metadata only: the server cannot read entries
    created_at: datetime


class AuditOut(BaseModel):
    seq: int
    ts: str
    actor_id: str | None
    action: str
    target_id: str | None
    detail: str
    ip: str | None


class AuditVerifyOut(BaseModel):
    valid: bool
    checked: int
    first_bad_seq: int | None
    reason: str | None
    head_seq: int | None
    head_hash: str | None


# ---------------------------------------------------------------- sharing
class KeypairIn(BaseModel):
    public_key: Key32
    wrapped_private_key: Blob


class LookupOut(BaseModel):
    id: str
    email: str
    public_key: str


class VaultCreate(BaseModel):
    id: uuid.UUID
    name_blob: Blob
    wrapped_key: Blob


class VaultOut(BaseModel):
    id: str
    name_blob: str
    key_version: int
    role: str
    wrapped_key: str
    created_at: datetime


class MemberOut(BaseModel):
    user_id: str
    email: str
    role: str
    public_key: str


class MemberAdd(BaseModel):
    user_id: str
    role: Literal["owner", "editor", "viewer"]
    wrapped_key: Blob
    key_version: int = Field(ge=1)


class RotatedEntry(BaseModel):
    id: str
    blob: LargeBlob
    version: int = Field(ge=1)       # the version being replaced (optimistic lock)


class RotateIn(BaseModel):
    """Sent when removing a member: a brand-new vault key, everything re-sealed."""
    key_version: int = Field(ge=2)
    name_blob: Blob
    member_keys: dict[str, Blob]     # user_id -> new vault key sealed to that user
    entries: list[RotatedEntry]


class SharedEntryCreate(BaseModel):
    id: uuid.UUID
    blob: LargeBlob
    key_version: int = Field(ge=1)


class SharedEntryUpdate(BaseModel):
    blob: LargeBlob
    version: int = Field(ge=1)
    key_version: int = Field(ge=1)


class SharedEntryOut(BaseModel):
    id: str
    blob: str
    version: int
    key_version: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class InviteIn(BaseModel):
    email: Email


class InviteOut(BaseModel):
    email: str
    code: str                 # shown exactly once
    expires_at: datetime
