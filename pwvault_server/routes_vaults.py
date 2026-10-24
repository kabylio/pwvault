"""Shared vaults. The server enforces WHO may do WHAT; it can never read
anything, because vault keys only ever exist sealed to individual users.

Roles: viewer (read) < editor (read/write entries) < owner (manage members).
Non-members get 404 (indistinguishable from a missing vault).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from . import security
from .audit import BoundAudit
from .db import SharedEntry, SharedVault, User, VaultMember
from .deps import current_user, get_audit, get_db
from .schemas import (LookupOut, MemberAdd, MemberOut, RotateIn, SharedEntryCreate,
                      SharedEntryOut, SharedEntryUpdate, VaultCreate, VaultOut,
                      b64d, b64e)
from pydantic import BaseModel
from typing import Literal


class RoleIn2(BaseModel):
    role: Literal["owner", "editor", "viewer"]

router = APIRouter(tags=["sharing"])
RANK = {"viewer": 1, "editor": 2, "owner": 3}


def _access(db: Session, user: User, vault_id: str, need: str = "viewer"):
    row = db.execute(
        select(SharedVault, VaultMember).join(VaultMember, VaultMember.vault_id == SharedVault.id)
        .where(SharedVault.id == vault_id, VaultMember.user_id == user.id)).first()
    if row is None:
        raise HTTPException(404, "Vault not found")
    vault, member = row
    if RANK[member.role] < RANK[need]:
        raise HTTPException(403, f"This action needs the '{need}' role")
    return vault, member


def _entry_out(e: SharedEntry, key_version: int) -> SharedEntryOut:
    return SharedEntryOut(id=e.id, blob=b64e(e.blob), version=e.version, key_version=key_version,
                          created_by=e.created_by, created_at=e.created_at, updated_at=e.updated_at)


# ----------------------------------------------------------- directory
@router.get("/users/lookup", response_model=LookupOut)
def lookup(email: str = Query(max_length=254), db: Session = Depends(get_db),
           _: User = Depends(current_user)):
    """Find a colleague's public key to share with them. Clients must compare
    fingerprints out of band: the server could otherwise substitute a key."""
    u = db.scalar(select(User).where(User.email == email.strip().lower()))
    if u is None or u.public_key is None or u.disabled:
        raise HTTPException(404, "No such user, or they have not set up sharing yet")
    return LookupOut(id=u.id, email=u.email, public_key=b64e(u.public_key))


# -------------------------------------------------------------- vaults
@router.post("/vaults", response_model=VaultOut, status_code=201)
def create_vault(body: VaultCreate, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    if user.public_key is None:
        raise HTTPException(409, "Set up your keypair first")
    vid = str(body.id)
    if db.get(SharedVault, vid) is not None:
        raise HTTPException(409, "Vault id already exists")
    now = security.utcnow()
    db.add(SharedVault(id=vid, name_blob=b64d(body.name_blob), key_version=1, created_at=now))
    db.add(VaultMember(vault_id=vid, user_id=user.id, role="owner",
                       wrapped_key=b64d(body.wrapped_key), created_at=now))
    db.commit()
    audit.record("vault.create", user.id, vid)
    return VaultOut(id=vid, name_blob=body.name_blob, key_version=1, role="owner",
                    wrapped_key=body.wrapped_key, created_at=now)


@router.get("/vaults", response_model=list[VaultOut])
def list_vaults(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.execute(
        select(SharedVault, VaultMember).join(VaultMember, VaultMember.vault_id == SharedVault.id)
        .where(VaultMember.user_id == user.id).order_by(SharedVault.created_at)).all()
    return [VaultOut(id=v.id, name_blob=b64e(v.name_blob), key_version=v.key_version, role=m.role,
                     wrapped_key=b64e(m.wrapped_key), created_at=v.created_at) for v, m in rows]


@router.delete("/vaults/{vault_id}", status_code=204)
def delete_vault(vault_id: str, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    _access(db, user, vault_id, "owner")
    db.execute(delete(SharedEntry).where(SharedEntry.vault_id == vault_id))
    db.execute(delete(VaultMember).where(VaultMember.vault_id == vault_id))
    db.execute(delete(SharedVault).where(SharedVault.id == vault_id))
    db.commit()
    audit.record("vault.delete", user.id, vault_id)
    return Response(status_code=204)


# ------------------------------------------------------------- members
@router.get("/vaults/{vault_id}/members", response_model=list[MemberOut])
def list_members(vault_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _access(db, user, vault_id)
    rows = db.execute(select(VaultMember, User).join(User, User.id == VaultMember.user_id)
                      .where(VaultMember.vault_id == vault_id).order_by(VaultMember.created_at)).all()
    return [MemberOut(user_id=u.id, email=u.email, role=m.role, public_key=b64e(u.public_key or b""))
            for m, u in rows]


@router.post("/vaults/{vault_id}/members", status_code=201)
def add_member(vault_id: str, body: MemberAdd, db: Session = Depends(get_db),
               user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    vault, _ = _access(db, user, vault_id, "owner")
    if body.key_version != vault.key_version:
        raise HTTPException(409, "Stale key version: the vault key was rotated, retry")
    target = db.get(User, body.user_id)
    if target is None or target.public_key is None or target.disabled:
        raise HTTPException(404, "No such user, or they have not set up sharing yet")
    if db.get(VaultMember, (vault_id, target.id)) is not None:
        raise HTTPException(409, "Already a member")
    db.add(VaultMember(vault_id=vault_id, user_id=target.id, role=body.role,
                       wrapped_key=b64d(body.wrapped_key), created_at=security.utcnow()))
    db.commit()
    audit.record("vault.member_add", user.id, vault_id, member=target.id, role=body.role)
    return {"user_id": target.id, "role": body.role}


@router.put("/vaults/{vault_id}/members/{user_id}/role", status_code=204)
def set_member_role(vault_id: str, user_id: str, body: RoleIn2, db: Session = Depends(get_db),
                    user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    _access(db, user, vault_id, "owner")
    member = db.get(VaultMember, (vault_id, user_id))
    if member is None:
        raise HTTPException(404, "Not a member")
    if member.role == "owner" and body.role != "owner":
        owners = db.scalar(select(func.count()).select_from(VaultMember)
                           .where(VaultMember.vault_id == vault_id, VaultMember.role == "owner"))
        if owners <= 1:
            raise HTTPException(409, "A vault must keep at least one owner")
    old, member.role = member.role, body.role
    db.commit()
    audit.record("vault.member_role", user.id, vault_id, member=user_id, old=old, new=body.role)
    return Response(status_code=204)


@router.post("/vaults/{vault_id}/members/{user_id}/remove", status_code=204)
def remove_member(vault_id: str, user_id: str, body: RotateIn, db: Session = Depends(get_db),
                  user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    """Removing someone ALSO rotates the vault key. The removed member still
    knows the old key, so everything is re-sealed under a new one, atomically.
    (Another owner must do this: a leaver must not generate the new key.)"""
    vault, _ = _access(db, user, vault_id, "owner")
    if user_id == user.id:
        raise HTTPException(409, "You cannot remove yourself; ask another owner")
    if db.get(VaultMember, (vault_id, user_id)) is None:
        raise HTTPException(404, "Not a member")
    if body.key_version != vault.key_version + 1:
        raise HTTPException(409, "key_version must be current + 1")

    remaining = {m.user_id: m for m in db.scalars(
        select(VaultMember).where(VaultMember.vault_id == vault_id, VaultMember.user_id != user_id))}
    if set(body.member_keys) != set(remaining):
        raise HTTPException(422, "member_keys must cover exactly the remaining members")
    current = {e.id: e for e in db.scalars(select(SharedEntry).where(SharedEntry.vault_id == vault_id))}
    if {e.id for e in body.entries} != set(current) or len(body.entries) != len(current):
        raise HTTPException(422, "entries must re-seal every entry in the vault, exactly once")
    if any(current[e.id].version != e.version for e in body.entries):
        raise HTTPException(409, "An entry changed while rotating; retry")

    now = security.utcnow()
    for e in body.entries:
        row = current[e.id]
        row.blob, row.version, row.updated_at = b64d(e.blob), row.version + 1, now
    for uid, wrapped in body.member_keys.items():
        remaining[uid].wrapped_key = b64d(wrapped)
    vault.name_blob, vault.key_version = b64d(body.name_blob), body.key_version
    db.delete(db.get(VaultMember, (vault_id, user_id)))
    db.commit()
    audit.record("vault.member_removed", user.id, vault_id, member=user_id,
                 new_key_version=body.key_version, entries_resealed=len(current))
    return Response(status_code=204)


# ------------------------------------------------------------- entries
def _check_kv(vault: SharedVault, key_version: int) -> None:
    if key_version != vault.key_version:
        raise HTTPException(409, "Stale key version: refresh your vault key and retry")


@router.get("/vaults/{vault_id}/entries", response_model=list[SharedEntryOut])
def list_entries(vault_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    vault, _ = _access(db, user, vault_id)
    rows = db.scalars(select(SharedEntry).where(SharedEntry.vault_id == vault_id)
                      .order_by(SharedEntry.created_at)).all()
    return [_entry_out(e, vault.key_version) for e in rows]


@router.post("/vaults/{vault_id}/entries", response_model=SharedEntryOut, status_code=201)
def create_entry(vault_id: str, body: SharedEntryCreate, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    vault, _ = _access(db, user, vault_id, "editor")
    _check_kv(vault, body.key_version)
    eid = str(body.id)
    if db.get(SharedEntry, eid) is not None:
        raise HTTPException(409, "Entry id already exists")
    now = security.utcnow()
    e = SharedEntry(id=eid, vault_id=vault_id, created_by=user.id, blob=b64d(body.blob),
                    version=1, created_at=now, updated_at=now)
    db.add(e)
    db.commit()
    audit.record("vault.entry_create", user.id, eid, vault=vault_id)
    return _entry_out(e, vault.key_version)


@router.get("/vaults/{vault_id}/entries/{entry_id}", response_model=SharedEntryOut)
def get_entry(vault_id: str, entry_id: str, db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    vault, _ = _access(db, user, vault_id)
    e = db.scalar(select(SharedEntry).where(SharedEntry.id == entry_id, SharedEntry.vault_id == vault_id))
    if e is None:
        raise HTTPException(404, "Entry not found")
    return _entry_out(e, vault.key_version)


@router.put("/vaults/{vault_id}/entries/{entry_id}", response_model=SharedEntryOut)
def update_entry(vault_id: str, entry_id: str, body: SharedEntryUpdate, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    vault, _ = _access(db, user, vault_id, "editor")
    _check_kv(vault, body.key_version)
    res = db.execute(update(SharedEntry).where(
        SharedEntry.id == entry_id, SharedEntry.vault_id == vault_id, SharedEntry.version == body.version)
        .values(blob=b64d(body.blob), version=SharedEntry.version + 1, updated_at=security.utcnow()))
    db.commit()
    e = db.scalar(select(SharedEntry).where(SharedEntry.id == entry_id, SharedEntry.vault_id == vault_id))
    if res.rowcount == 0:
        raise HTTPException(404 if e is None else 409,
                            "Entry not found" if e is None else "Version conflict: entry was changed elsewhere")
    audit.record("vault.entry_update", user.id, entry_id, vault=vault_id)
    return _entry_out(e, vault.key_version)


@router.delete("/vaults/{vault_id}/entries/{entry_id}", status_code=204)
def delete_entry(vault_id: str, entry_id: str, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    _access(db, user, vault_id, "editor")
    res = db.execute(delete(SharedEntry).where(SharedEntry.id == entry_id, SharedEntry.vault_id == vault_id))
    db.commit()
    if res.rowcount == 0:
        raise HTTPException(404, "Entry not found")
    audit.record("vault.entry_delete", user.id, entry_id, vault=vault_id)
    return Response(status_code=204)
