"""WebAuthn passkeys: device registration and second-factor login."""
from __future__ import annotations

import json
import base64
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session
from webauthn import (base64url_to_bytes,
                      generate_authentication_options,
                      generate_registration_options,
                      verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)

from . import security
from .audit import BoundAudit
from .db import PasskeyChallenge, PasskeyCredential, User
from .deps import current_user, get_audit, get_db, get_settings
from .routes_auth import _check_lock, _fail, _require_second_factor
from .schemas import (PasskeyAuthOptionsIn, PasskeyRegistrationIn,
                      PasskeyRegistrationOptionsIn, PasskeyRemovalIn, b64e)

router = APIRouter(prefix="/auth/passkeys", tags=["passkeys"])
CHALLENGE_TTL = timedelta(minutes=5)


def _challenge(db: Session, user: User, purpose: str, value: bytes) -> str:
    db.execute(delete(PasskeyChallenge).where(
        PasskeyChallenge.user_id == user.id,
        (PasskeyChallenge.created_at < security.utcnow() - CHALLENGE_TTL) |
        PasskeyChallenge.used.is_(True)))
    challenge_id = str(uuid.uuid4())
    db.add(PasskeyChallenge(id=challenge_id, user_id=user.id, challenge=value,
                            purpose=purpose, created_at=security.utcnow(), used=False))
    db.commit()
    return challenge_id


def _consume(db: Session, user_id: str, challenge_id: str, purpose: str) -> bytes:
    row = db.scalar(select(PasskeyChallenge).where(
        PasskeyChallenge.id == challenge_id, PasskeyChallenge.user_id == user_id,
        PasskeyChallenge.purpose == purpose, PasskeyChallenge.used.is_(False)))
    if row is None or row.created_at < security.utcnow() - CHALLENGE_TTL:
        raise ValueError("Passkey challenge expired or already used")
    challenge = row.challenge
    changed = db.execute(update(PasskeyChallenge).where(
        PasskeyChallenge.id == challenge_id, PasskeyChallenge.used.is_(False)
    ).values(used=True).execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("Passkey challenge already used")
    db.commit()  # consume before cryptographic verification; failed assertions cannot be replayed
    return challenge


@router.get("")
def list_passkeys(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [{"id": p.credential_id, "name": p.name, "created_at": p.created_at,
             "last_used_at": p.last_used_at}
            for p in db.scalars(select(PasskeyCredential).where(
                PasskeyCredential.user_id == user.id).order_by(PasskeyCredential.created_at)).all()]


@router.post("/registration-options")
def registration_options(body: PasskeyRegistrationOptionsIn,
                         db: Session = Depends(get_db), user: User = Depends(current_user),
                         s=Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.auth_key):
        raise _fail(db, user, s, audit, "bad_passkey_enrolment_password")
    _require_second_factor(db, user, s, audit, body.otp, body.recovery_code,
                           body.passkey_challenge_id, body.passkey_assertion,
                           "bad_passkey_enrolment_factor")
    existing = db.scalars(select(PasskeyCredential).where(
        PasskeyCredential.user_id == user.id)).all()
    options = generate_registration_options(
        rp_id=s.webauthn_rp_id, rp_name="PWVault", user_id=user.id.encode(),
        user_name=user.email, user_display_name=user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
                             for p in existing])
    cid = _challenge(db, user, "register", options.challenge)
    return {"challenge_id": cid, "options": json.loads(options_to_json(options))}


@router.post("/register")
def register_passkey(body: PasskeyRegistrationIn, db: Session = Depends(get_db),
                     user: User = Depends(current_user), s=Depends(get_settings),
                     audit: BoundAudit = Depends(get_audit)):
    try:
        challenge = _consume(db, user.id, body.challenge_id, "register")
        verified = verify_registration_response(
            credential=body.credential, expected_challenge=challenge,
            expected_rp_id=s.webauthn_rp_id, expected_origin=s.webauthn_origin,
            require_user_verification=True)
    except Exception as exc:
        raise HTTPException(400, "Passkey registration could not be verified") from exc
    credential_id = base64.urlsafe_b64encode(verified.credential_id).rstrip(b"=").decode("ascii")
    if db.get(PasskeyCredential, credential_id):
        raise HTTPException(409, "This passkey is already registered")
    db.add(PasskeyCredential(credential_id=credential_id, user_id=user.id,
        public_key=verified.credential_public_key, sign_count=verified.sign_count,
        name=body.name.strip() or "Passkey", created_at=security.utcnow()))
    db.commit()
    audit.record("auth.passkey.add", user.id, user.id)
    return {"ok": True}


@router.delete("/{credential_id}", status_code=204)
def remove_passkey(credential_id: str, body: PasskeyRemovalIn,
                   db: Session = Depends(get_db),
                   s=Depends(get_settings),
                   user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    _check_lock(user, audit)
    if not security.verify_auth_key(user.auth_hash, body.auth_key):
        raise _fail(db, user, s, audit, "bad_passkey_removal_password")
    _require_second_factor(db, user, s, audit, body.otp, body.recovery_code,
                           body.passkey_challenge_id, body.passkey_assertion,
                           "bad_passkey_removal_factor")
    result = db.execute(delete(PasskeyCredential).where(
        PasskeyCredential.credential_id == credential_id,
        PasskeyCredential.user_id == user.id))
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(404, "Passkey not found")
    audit.record("auth.passkey.remove", user.id, user.id)
    from fastapi import Response
    return Response(status_code=204)


@router.post("/authentication-options")
def authentication_options(body: PasskeyAuthOptionsIn, db: Session = Depends(get_db),
                           s=Depends(get_settings), audit: BoundAudit = Depends(get_audit)):
    user = db.scalar(select(User).where(User.email == body.email))
    if user is None:
        security.verify_auth_key(security.DUMMY_HASH, body.auth_key)
        audit.record("auth.failure", reason="unknown_account")
        raise HTTPException(401, "Invalid credentials")
    _check_lock(user, audit)
    if user.disabled or not security.verify_auth_key(user.auth_hash, body.auth_key):
        if user.disabled:
            raise HTTPException(403, "Account disabled. Contact an administrator.")
        raise _fail(db, user, s, audit, "bad_passkey_preflight")
    rows = db.scalars(select(PasskeyCredential).where(
        PasskeyCredential.user_id == user.id)).all()
    if not rows:
        raise HTTPException(404, "No passkeys are registered")
    options = generate_authentication_options(
        rp_id=s.webauthn_rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
                           for p in rows],
        user_verification=UserVerificationRequirement.REQUIRED)
    challenge_id = _challenge(db, user, "login", options.challenge)
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


def verify_login_passkey(db: Session, user: User, challenge_id: str,
                         credential: dict, s) -> bool:
    try:
        challenge = _consume(db, user.id, challenge_id, "login")
        credential_id = credential.get("id", "")
        row = db.get(PasskeyCredential, credential_id)
        if row is None or row.user_id != user.id:
            return False
        verified = verify_authentication_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=s.webauthn_rp_id, expected_origin=s.webauthn_origin,
            credential_public_key=row.public_key,
            credential_current_sign_count=row.sign_count,
            require_user_verification=True)
        row.sign_count = verified.new_sign_count
        row.last_used_at = security.utcnow()
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
