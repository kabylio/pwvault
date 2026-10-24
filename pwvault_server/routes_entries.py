"""Encrypted entry CRUD. Every query is scoped to the authenticated user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from . import security
from .db import Entry, EntryRevision, User
from .audit import BoundAudit
from .deps import current_user, get_audit, get_db
from .schemas import EntryCreate, EntryOut, EntryUpdate, b64d, b64e

router = APIRouter(prefix="/entries", tags=["entries"])


def _out(e: Entry) -> EntryOut:
    return EntryOut(id=e.id, blob=b64e(e.blob), version=e.version,
                    created_at=e.created_at, updated_at=e.updated_at)


def _owned(db: Session, user: User, entry_id: str) -> Entry | None:
    # Other users' entries are indistinguishable from missing ones (404).
    return db.scalar(select(Entry).where(Entry.id == entry_id,
                                         Entry.user_id == user.id))


@router.get("", response_model=list[EntryOut])
def list_entries(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(Entry).where(Entry.user_id == user.id)
                      .order_by(Entry.created_at)).all()
    return [_out(e) for e in rows]


@router.post("", response_model=EntryOut, status_code=201)
def create_entry(body: EntryCreate, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    entry_id = str(body.id)
    if db.get(Entry, entry_id) is not None:
        raise HTTPException(409, "Entry id already exists")
    now = security.utcnow()
    entry = Entry(id=entry_id, user_id=user.id, blob=b64d(body.blob),
                  version=1, created_at=now, updated_at=now)
    db.add(entry)
    db.commit()
    audit.record("entry.create", user.id, entry_id)
    return _out(entry)


@router.get("/{entry_id}", response_model=EntryOut)
def get_entry(entry_id: str, db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    entry = _owned(db, user, entry_id)
    if entry is None:
        raise HTTPException(404, "Entry not found")
    return _out(entry)


@router.get("/{entry_id}/history")
def entry_history(entry_id: str, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    if _owned(db, user, entry_id) is None:
        raise HTTPException(404, "Entry not found")
    rows = db.scalars(select(EntryRevision).where(
        EntryRevision.entry_id == entry_id, EntryRevision.user_id == user.id
    ).order_by(EntryRevision.version.desc()).limit(10)).all()
    return [{"id": r.id, "version": r.version, "blob": b64e(r.blob),
             "created_at": r.created_at} for r in rows]


@router.put("/{entry_id}", response_model=EntryOut)
def update_entry(entry_id: str, body: EntryUpdate, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    # One atomic UPDATE: succeeds only if the caller saw the latest version.
    old = _owned(db, user, entry_id)
    if old is None:
        raise HTTPException(404, "Entry not found")
    result = db.execute(
        update(Entry)
        .where(Entry.id == entry_id, Entry.user_id == user.id,
               Entry.version == body.version)
        .values(blob=b64d(body.blob), version=Entry.version + 1,
                updated_at=security.utcnow())
        .execution_options(synchronize_session=False))
    if result.rowcount == 0:
        raise HTTPException(409, "Version conflict: entry was changed elsewhere")
    db.add(EntryRevision(entry_id=entry_id, user_id=user.id, blob=old.blob,
                         version=old.version, created_at=old.updated_at))
    # Keep a short bounded history because revisions may contain encrypted files.
    stale = db.scalars(select(EntryRevision.id).where(
        EntryRevision.entry_id == entry_id, EntryRevision.user_id == user.id
    ).order_by(EntryRevision.version.desc()).offset(10)).all()
    if stale:
        db.execute(delete(EntryRevision).where(EntryRevision.id.in_(stale)))
    db.commit()
    audit.record("entry.update", user.id, entry_id)
    db.expire(old)
    return _out(_owned(db, user, entry_id))


@router.delete("/{entry_id}", status_code=204)
def delete_entry(entry_id: str, db: Session = Depends(get_db),
                 user: User = Depends(current_user), audit: BoundAudit = Depends(get_audit)):
    db.execute(delete(EntryRevision).where(EntryRevision.entry_id == entry_id,
                                            EntryRevision.user_id == user.id))
    result = db.execute(delete(Entry).where(Entry.id == entry_id,
                                            Entry.user_id == user.id))
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(404, "Entry not found")
    audit.record("entry.delete", user.id, entry_id)
    return Response(status_code=204)
