"""Registration, login, 2FA and password change."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import security
from .config import Settings
from .db import Invite, PasskeyCredential, RecoveryCode, User
from .audit import BoundAudit
from .deps import current_user, get_audit, get_db, get_settings
from .schemas import (ChangePasswordIn, Kdf, LoginIn, LoginOut, MeOut,
                      PreloginIn, PreloginOut, RegisterIn, TotpDisableIn,
                      KeypairIn, TotpEnableIn, TotpEnableOut, TotpSetupIn,
                      TotpSetupOut, b64d, b64e)

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID = "Invalid credentials"
DEFAULT_KDF = Kdf(time_cost=3, memory_cost_kib=65536, parallelism=4)


@router.get("/registration-policy")
def registration_policy(s: Settings = Depends(get_settings)):
    """Expose only the public signup mode needed to render the registration form."""
    return {"invite_required": s.registration == "invite"}


def _check_kdf(kdf: Kdf, s: Settings) -> None:
    if (kdf.time_cost < s.min_time_cost or kdf.memory_cost_kib < s.min_memory_kib
            or kdf.parallelism < s.min_parallelism):
        raise HTTPException(422, "KDF parameters are below the server minimum")


def _fail(db: Session, user: User, s: Settings, audit: BoundAudit, reason: str,
          detail: str = INVALID, status: int = 401) -> HTTPException:
    """Count a failed attempt, lock the account after too many, and audit both."""
    user.failed_attempts += 1
    locked = user.failed_attempts >= s.max_failed_attempts
    if locked:
        user.locked_until = security.utcnow() + _minutes(s.lockout_minutes)
        user.failed_attempts = 0
    db.commit()
    audit.record("auth.failure", user.id, user.id, reason=reason)
    if locked:
        audit.record("auth.lockout", user.id, user.id, minutes=s.lockout_minutes)
    return HTTPException(status, detail)


def _minutes(n: int):
    from datetime import timedelta
    return timedelta(minutes=n)


def _check_lock(user: User, audit: BoundAudit) -> None:
    now = security.utcnow()
    if user.locked_until and user.locked_until > now:
        audit.record("auth.blocked_locked", user.id, user.id)
        wait = int((user.locked_until - now).total_seconds()) + 1
        raise HTTPException(429, "Account temporarily locked",
                            headers={"Retry-After": str(wait)})


def _second_factor_ok(db: Session, user: User, s: Settings,
                      otp: str | None, recovery_code: str | None) -> bool:
    if otp:
        if not user.totp_enabled or user.totp_secret_enc is None:
            return False
        secret = security.decrypt_secret(s, user.id, user.totp_secret_enc)
        step = security.verify_totp(secret, otp, user.totp_last_step)
        if step is None:
            return False
        # The conditional write makes code consumption atomic across workers;
        # two simultaneous requests cannot both accept the same time step.
        consumed = db.execute(update(User).where(
            User.id == user.id, User.totp_last_step < step
        ).values(totp_last_step=step).execution_options(synchronize_session=False))
        if consumed.rowcount != 1:
            return False
        user.totp_last_step = step
        return True
    if recovery_code:
        h = security.hash_recovery_code(recovery_code)
        row = db.scalar(select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.code_hash == h,
            RecoveryCode.used.is_(False)))
        if row is None:
            return False
        consumed = db.execute(update(RecoveryCode).where(
            RecoveryCode.id == row.id, RecoveryCode.used.is_(False)
        ).values(used=True).execution_options(synchronize_session=False))
        if consumed.rowcount != 1:
            return False
        row.used = True                     # single use
        return True
    return False


def _require_second_factor(db: Session, user: User, s: Settings, audit: BoundAudit,
                           otp: str | None, recovery_code: str | None,
                           passkey_challenge_id: str | None = None,
                           passkey_assertion: dict | None = None,
                           reason: str = "bad_step_up_factor") -> None:
    has_passkey = db.scalar(select(PasskeyCredential.credential_id).where(
        PasskeyCredential.user_id == user.id).limit(1)) is not None
    if not user.totp_enabled and not has_passkey:
        return
    if not otp and not recovery_code and not passkey_assertion:
        raise HTTPException(401, "otp_required")
    if passkey_assertion:
        from .routes_passkeys import verify_login_passkey
        valid = verify_login_passkey(db, user, passkey_challenge_id or "",
                                     passkey_assertion, s)
    elif otp and not user.totp_enabled:
        valid = False
    else:
        valid = _second_factor_ok(db, user, s, otp, recovery_code)
    if not valid:
        raise _fail(db, user, s, audit, reason)


def _issue(user: User, s: Settings) -> LoginOut:
    return LoginOut(
        access_token=security.create_token(s, user.id, user.token_version),
        expires_in=s.token_minutes * 60,
        wrapped_key=b64e(user.wrapped_key),
        public_key=b64e(user.public_key) if user.public_key else None,
        wrapped_private_key=b64e(user.wrapped_private_key) if user.wrapped_private_key else None)


# --------------------------------------------------------------- endpoints
@router.post("/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db),
             s: Settings = Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    _check_kdf(body.kdf, s)
    invite = None
    if s.registration == "invite" and body.email not in s.admin_emails:
        invite = db.scalar(select(Invite).where(
            Invite.email == body.email, Invite.used.is_(False), Invite.expires_at > security.utcnow(),
            Invite.code_hash == security.hash_recovery_code(body.invite_code or "")))
        if invite is None:
            raise HTTPException(403, "A valid invitation code is required to register")
    if db.scalar(select(User.id).where(User.email == body.email)):
        raise HTTPException(409, "Email already registered")
    user = User(
        id=str(uuid.uuid4()), email=body.email,
        auth_hash=security.hash_auth_key(body.auth_key),
        salt=b64d(body.salt), kdf_time_cost=body.kdf.time_cost,
        kdf_memory_kib=body.kdf.memory_cost_kib,
        kdf_parallelism=body.kdf.parallelism,
        wrapped_key=b64d(body.wrapped_key), created_at=security.utcnow(),
        role="admin" if body.email in s.admin_emails else "employee")
    if invite is not None:
        invite.used = True            # single use
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Email already registered") from None
    audit.record("auth.register", user.id, user.id, role=user.role)
    return {"id": user.id}


@router.post("/prelogin", response_model=PreloginOut)
def prelogin(body: PreloginIn, db: Session = Depends(get_db),
             s: Settings = Depends(get_settings)):
    user = db.scalar(select(User).where(User.email == body.email))
    if user is None:    # identical shape for unknown accounts
        return PreloginOut(salt=b64e(security.fake_salt(s, body.email)),
                           kdf=DEFAULT_KDF)
    return PreloginOut(
        salt=b64e(user.salt),
        kdf=Kdf(time_cost=user.kdf_time_cost,
                memory_cost_kib=user.kdf_memory_kib,
                parallelism=user.kdf_parallelism))


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, db: Session = Depends(get_db),
          s: Settings = Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    user = db.scalar(select(User).where(User.email == body.email))
    if user is None:
        security.verify_auth_key(security.DUMMY_HASH, body.auth_key)  # same cost
        audit.record("auth.failure", reason="unknown_account")  # no e-mail logged
        raise HTTPException(401, INVALID)
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.auth_key):
        raise _fail(db, user, s, audit, "bad_password")
    if user.disabled:    # only revealed AFTER the password was correct
        audit.record("auth.blocked_disabled", user.id, user.id)
        raise HTTPException(403, "Account disabled. Contact an administrator.")
    passkeys_exist = db.scalar(select(PasskeyCredential.credential_id).where(
        PasskeyCredential.user_id == user.id).limit(1)) is not None
    passkey_ok = False
    if user.totp_enabled or passkeys_exist:
        if not body.otp and not body.recovery_code and not body.passkey_assertion:
            raise HTTPException(401, "otp_required")   # not counted as a failure
        if body.passkey_assertion:
            from .routes_passkeys import verify_login_passkey
            passkey_ok = verify_login_passkey(db, user, body.passkey_challenge_id or "",
                                              body.passkey_assertion, s)
        else:
            passkey_ok = _second_factor_ok(db, user, s, body.otp, body.recovery_code)
        if not passkey_ok:
            raise _fail(db, user, s, audit, "bad_second_factor")
    elif body.passkey_assertion:
        raise _fail(db, user, s, audit, "unexpected_second_factor")
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    audit.record("auth.login", user.id, user.id,
                 method="passkey" if body.passkey_assertion else
                 ("recovery_code" if body.recovery_code else ("otp" if body.otp else "password")))
    return _issue(user, s)


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(current_user)):
    return MeOut(id=user.id, email=user.email, role=user.role,
                 totp_enabled=user.totp_enabled, created_at=user.created_at,
                 public_key=b64e(user.public_key) if user.public_key else None)


@router.post("/2fa/setup", response_model=TotpSetupOut)
def totp_setup(body: TotpSetupIn, db: Session = Depends(get_db),
               user: User = Depends(current_user), s: Settings = Depends(get_settings),
               audit: BoundAudit = Depends(get_audit)):
    if user.totp_enabled:
        raise HTTPException(409, "2FA is already enabled")
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.auth_key):
        raise _fail(db, user, s, audit, "bad_2fa_setup_password",
                    detail="Master password confirmation failed", status=403)
    _require_second_factor(db, user, s, audit, body.otp, body.recovery_code,
                           body.passkey_challenge_id, body.passkey_assertion,
                           "bad_2fa_setup_factor")
    secret = security.new_totp_secret()
    user.totp_secret_enc = security.encrypt_secret(s, user.id, secret)
    db.commit()
    return TotpSetupOut(secret=secret,
                        otpauth_uri=security.provisioning_uri(secret, user.email))


@router.post("/2fa/enable", response_model=TotpEnableOut)
def totp_enable(body: TotpEnableIn, db: Session = Depends(get_db),
                user: User = Depends(current_user),
                s: Settings = Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    if user.totp_enabled:
        raise HTTPException(409, "2FA is already enabled")
    if user.totp_secret_enc is None:
        raise HTTPException(409, "Call /auth/2fa/setup first")
    secret = security.decrypt_secret(s, user.id, user.totp_secret_enc)
    step = security.verify_totp(secret, body.code, 0)
    if step is None:
        raise HTTPException(400, "Invalid code")
    enabled = db.execute(update(User).where(
        User.id == user.id, User.totp_enabled.is_(False),
        User.totp_last_step < step, User.totp_secret_enc.is_not(None)
    ).values(totp_enabled=True, totp_last_step=step).execution_options(synchronize_session=False))
    if enabled.rowcount != 1:
        raise HTTPException(409, "2FA setup changed; start again")
    codes = security.generate_recovery_codes()
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    db.add_all(RecoveryCode(user_id=user.id,
                            code_hash=security.hash_recovery_code(c)) for c in codes)
    user.totp_enabled = True
    user.totp_last_step = step
    db.commit()
    audit.record("auth.2fa_enabled", user.id, user.id)
    return TotpEnableOut(recovery_codes=codes)     # shown exactly once


@router.post("/2fa/disable", status_code=204)
def totp_disable(body: TotpDisableIn, db: Session = Depends(get_db),
                 user: User = Depends(current_user),
                 s: Settings = Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    """A stolen access token alone must not be able to remove 2FA, so we ask
    for the auth key AND a second-factor code again."""
    if not user.totp_enabled:
        raise HTTPException(409, "2FA is not enabled")
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.auth_key) or \
            not _second_factor_ok(db, user, s, body.otp, body.recovery_code):
        raise _fail(db, user, s, audit, "bad_credentials_2fa_disable")
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = 0
    db.commit()
    audit.record("auth.2fa_disabled", user.id, user.id)


@router.post("/change-password", response_model=LoginOut)
def change_password(body: ChangePasswordIn, db: Session = Depends(get_db),
                    user: User = Depends(current_user),
                    s: Settings = Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    _check_kdf(body.new_kdf, s)
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.current_auth_key):
        raise _fail(db, user, s, audit, "bad_password_change")
    passkeys_exist = db.scalar(select(PasskeyCredential.credential_id).where(
        PasskeyCredential.user_id == user.id).limit(1)) is not None
    if user.totp_enabled or passkeys_exist:
        if not body.otp and not body.recovery_code:
            if not body.passkey_assertion:
                raise HTTPException(401, "otp_required")
        factor_ok = False
        if body.passkey_assertion:
            from .routes_passkeys import verify_login_passkey
            factor_ok = verify_login_passkey(db, user, body.passkey_challenge_id or "",
                                             body.passkey_assertion, s)
        elif body.otp or body.recovery_code:
            factor_ok = _second_factor_ok(db, user, s, body.otp, body.recovery_code)
        if not factor_ok:
            raise _fail(db, user, s, audit, "bad_second_factor_password_change")
    if user.public_key is not None and body.new_wrapped_private_key is None:
        raise HTTPException(422, "new_wrapped_private_key is required (your private key is sealed under the old password)")
    if body.new_wrapped_private_key is not None and user.public_key is not None:
        user.wrapped_private_key = b64d(body.new_wrapped_private_key)
    user.auth_hash = security.hash_auth_key(body.new_auth_key)
    user.salt = b64d(body.new_salt)
    user.kdf_time_cost = body.new_kdf.time_cost
    user.kdf_memory_kib = body.new_kdf.memory_cost_kib
    user.kdf_parallelism = body.new_kdf.parallelism
    user.wrapped_key = b64d(body.new_wrapped_key)
    user.token_version += 1          # every previously issued token dies now
    db.commit()
    audit.record("auth.password_changed", user.id, user.id)
    return _issue(user, s)


@router.put("/keypair", status_code=204)
def set_keypair(body: KeypairIn, db: Session = Depends(get_db),
                user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    """One-time: publish your X25519 public key plus your private key sealed
    under your own enc_key (the server cannot open it). Immutable afterwards,
    so the server cannot quietly swap in a different key."""
    if user.public_key is not None:
        raise HTTPException(409, "Keypair already set")
    user.public_key = b64d(body.public_key)
    user.wrapped_private_key = b64d(body.wrapped_private_key)
    db.commit()
    audit.record("auth.keypair_created", user.id, user.id)
