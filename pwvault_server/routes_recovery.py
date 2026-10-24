"""Client-side encrypted recovery for a lost master password."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .audit import BoundAudit
from .db import User
from .deps import current_user, get_audit, get_db, get_settings
from .routes_auth import (_check_kdf, _check_lock, _fail, _issue,
                          _require_second_factor)
from .schemas import (RecoveryCompleteIn, RecoveryOptionsIn, RecoveryOptionsOut,
                      RecoverySetupIn, b64d, b64e)

router = APIRouter(prefix="/auth/recovery", tags=["recovery"])


@router.post("/setup")
def setup_recovery(body: RecoverySetupIn, db: Session = Depends(get_db),
                   user: User = Depends(current_user), s=Depends(get_settings),
                   audit: BoundAudit = Depends(get_audit)):
    if not security.verify_auth_key(user.auth_hash, body.auth_key):
        raise _fail(db, user, s, audit, "bad_recovery_setup_password")
    if user.public_key and body.recovery_wrapped_private_key is None:
        raise HTTPException(422, "A recovery copy of the account private key is required")
    _require_second_factor(db, user, s, audit, body.otp, body.recovery_code,
                           body.passkey_challenge_id, body.passkey_assertion,
                           "bad_recovery_setup_factor")
    user.recovery_salt = b64d(body.recovery_salt)
    user.recovery_auth_hash = security.hash_auth_key(body.recovery_auth_key)
    user.recovery_wrapped_key = b64d(body.recovery_wrapped_key)
    user.recovery_wrapped_private_key = (b64d(body.recovery_wrapped_private_key)
                                         if body.recovery_wrapped_private_key else None)
    db.commit()
    audit.record("auth.recovery.setup", user.id, user.id)
    return {"ok": True}


@router.post("/options", response_model=RecoveryOptionsOut)
def recovery_options(body: RecoveryOptionsIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email))
    if user and user.recovery_salt and user.recovery_wrapped_key:
        # The app wraps 32-byte keys, so each AES-GCM envelope is 60 bytes.
        # Return indistinguishable fixed-size placeholders for missing values
        # to avoid exposing account/recovery state through response length.
        return RecoveryOptionsOut(recovery_salt=b64e(user.recovery_salt),
            recovery_wrapped_key=b64e(user.recovery_wrapped_key),
            recovery_wrapped_private_key=(b64e(user.recovery_wrapped_private_key)
                                          if user.recovery_wrapped_private_key
                                          else b64e(secrets.token_bytes(60))))
    # Same-shaped, same-length response for unknown accounts and accounts
    # without recovery configured. The client will fail GCM verification.
    return RecoveryOptionsOut(recovery_salt=b64e(secrets.token_bytes(16)),
        recovery_wrapped_key=b64e(secrets.token_bytes(60)),
        recovery_wrapped_private_key=b64e(secrets.token_bytes(60)))


@router.post("/complete")
def complete_recovery(body: RecoveryCompleteIn, db: Session = Depends(get_db),
                      s=Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    user = db.scalar(select(User).where(User.email == body.email))
    if user is None:
        security.verify_auth_key(security.DUMMY_HASH, body.recovery_auth_key)
        audit.record("auth.failure", reason="unknown_recovery_account")
        raise HTTPException(401, "Invalid recovery information")
    _check_lock(user, audit)
    if not user.recovery_auth_hash or not security.verify_auth_key(
            user.recovery_auth_hash, body.recovery_auth_key):
        raise _fail(db, user, s, audit, "bad_recovery_key", "Invalid recovery information")
    if user.disabled:
        audit.record("auth.blocked_disabled", user.id, user.id)
        raise HTTPException(403, "Account disabled. Contact an administrator.")
    _check_kdf(body.new_kdf, s)
    if user.public_key and body.new_wrapped_private_key is None:
        raise HTTPException(422, "A re-wrapped account private key is required")
    if user.totp_enabled:
        if not body.otp and not body.recovery_code:
            raise HTTPException(401, "otp_required")
        if not _second_factor_ok(db, user, s, body.otp, body.recovery_code):
            raise _fail(db, user, s, audit, "bad_recovery_second_factor", "Invalid recovery information")
    user.auth_hash = security.hash_auth_key(body.new_auth_key)
    user.salt = b64d(body.new_salt)
    user.kdf_time_cost = body.new_kdf.time_cost
    user.kdf_memory_kib = body.new_kdf.memory_cost_kib
    user.kdf_parallelism = body.new_kdf.parallelism
    user.wrapped_key = b64d(body.new_wrapped_key)
    if body.new_wrapped_private_key:
        user.wrapped_private_key = b64d(body.new_wrapped_private_key)
    user.token_version += 1
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    audit.record("auth.recovery.complete", user.id, user.id)
    return _issue(user, s)
