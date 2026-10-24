"""Administrator console. Admins manage ACCOUNTS; they can never read vault
contents, because the server only holds ciphertext (zero-knowledge)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import security
from .audit import BoundAudit
from .db import Entry, Invite, User
from .deps import get_audit, get_db, require_admin
from .schemas import AdminUserOut, AuditOut, AuditVerifyOut, InviteIn, InviteOut, RoleIn

router = APIRouter(prefix="/admin", tags=["admin"])


def _target(db: Session, admin: User, user_id: str, *, allow_self: bool = False) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == admin.id and not allow_self:
        raise HTTPException(409, "Administrators cannot do this to their own account")
    return user


@router.get("/users", response_model=list[AdminUserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    counts = dict(db.execute(select(Entry.user_id, func.count()).group_by(Entry.user_id)).all())
    now = security.utcnow()
    return [AdminUserOut(
        id=u.id, email=u.email, role=u.role, disabled=u.disabled,
        locked=bool(u.locked_until and u.locked_until > now),
        totp_enabled=u.totp_enabled, entry_count=counts.get(u.id, 0),
        created_at=u.created_at) for u in db.scalars(select(User).order_by(User.created_at))]


@router.put("/users/{user_id}/role", status_code=204)
def set_role(user_id: str, body: RoleIn, db: Session = Depends(get_db),
             admin: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    user = _target(db, admin, user_id)
    old, user.role = user.role, body.role
    db.commit()
    audit.record("admin.role_change", admin.id, user.id, old=old, new=body.role)


@router.post("/users/{user_id}/disable", status_code=204)
def disable_user(user_id: str, db: Session = Depends(get_db),
                 admin: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    user = _target(db, admin, user_id)
    user.disabled = True
    user.token_version += 1            # kills every live session immediately
    db.commit()
    audit.record("admin.user_disabled", admin.id, user.id)


@router.post("/users/{user_id}/enable", status_code=204)
def enable_user(user_id: str, db: Session = Depends(get_db),
                admin: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    user = _target(db, admin, user_id)
    user.disabled = False
    db.commit()
    audit.record("admin.user_enabled", admin.id, user.id)


@router.post("/users/{user_id}/unlock", status_code=204)
def unlock_user(user_id: str, db: Session = Depends(get_db),
                admin: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    user = _target(db, admin, user_id, allow_self=True)
    user.failed_attempts, user.locked_until = 0, None
    db.commit()
    audit.record("admin.user_unlocked", admin.id, user.id)


@router.get("/audit", response_model=list[AuditOut])
def read_audit(limit: int = Query(100, ge=1, le=500), before_seq: int | None = None,
               _: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    return audit._log.list(limit, before_seq)


@router.get("/audit/verify", response_model=AuditVerifyOut)
def verify_audit(_: User = Depends(require_admin), audit: BoundAudit = Depends(get_audit)):
    return audit._log.verify()


@router.post("/invites", response_model=InviteOut, status_code=201)
def create_invite(body: InviteIn, db: Session = Depends(get_db), admin: User = Depends(require_admin),
                  audit: BoundAudit = Depends(get_audit)):
    """One single-use code per e-mail, valid 7 days. Share it through a private channel."""
    from datetime import timedelta
    if db.scalar(select(User.id).where(User.email == body.email)):
        raise HTTPException(409, "That e-mail already has an account")
    for old in db.scalars(select(Invite).where(Invite.email == body.email, Invite.used.is_(False))):
        db.delete(old)                      # a new invite replaces any pending one
    code = security.generate_recovery_codes(1)[0]
    expires = security.utcnow() + timedelta(days=7)
    db.add(Invite(email=body.email, code_hash=security.hash_recovery_code(code),
                  created_by=admin.id, expires_at=expires))
    db.commit()
    audit.record("admin.invite_created", admin.id, None)       # the address is not logged
    return InviteOut(email=body.email, code=code, expires_at=expires)
