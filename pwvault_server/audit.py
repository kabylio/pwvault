"""Tamper-evident audit log.

record_n = HMAC(k, hash_{n-1} || canonical(record_n)), hash_0 = "00..0".

* Editing any field of any record breaks its hash.
* Deleting or reordering records breaks the seq / prev_hash chain.
* HMAC (not a bare hash) means someone with database access but without the
  server key cannot recompute a valid chain after editing.
* Known limit: deleting the *newest* records is only detectable if the head
  (seq, hash) was recorded elsewhere - /admin/audit/verify returns it so it can
  be anchored externally (e.g. printed, emailed, written to WORM storage).
Secrets (passwords, keys, entry contents) are never written here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import security
from .db import AuditRecord

GENESIS = "0" * 64
_FIELDS = ("seq", "ts", "actor_id", "action", "target_id", "detail", "ip")


class AuditLog:
    def __init__(self, session_factory, server_key: bytes):
        self._sf = session_factory
        self._key = hmac.new(server_key, b"pwvault:audit-chain:v1", hashlib.sha256).digest()
        self._lock = threading.Lock()      # one writer per process; PK is the safety net

    def _mac(self, prev_hash: str, rec: dict) -> str:
        canon = json.dumps({k: rec[k] for k in _FIELDS}, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._key, f"{prev_hash}|{canon}".encode(), hashlib.sha256).hexdigest()

    def record(self, action: str, actor_id: str | None = None, target_id: str | None = None,
               detail: dict | None = None, ip: str | None = None) -> int:
        detail_s = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
        ts = security.utcnow().isoformat(timespec="seconds") + "Z"
        with self._lock:
            for _ in range(5):             # retry if another worker took our seq
                with self._sf() as db:
                    last = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))
                    seq = last.seq + 1 if last else 1
                    prev = last.hash if last else GENESIS
                    rec = dict(seq=seq, ts=ts, actor_id=actor_id, action=action,
                               target_id=target_id, detail=detail_s, ip=ip)
                    db.add(AuditRecord(**rec, prev_hash=prev, hash=self._mac(prev, rec)))
                    try:
                        db.commit()
                        return seq
                    except IntegrityError:
                        db.rollback()
        raise RuntimeError("could not append audit record")

    def verify(self) -> dict:
        prev, count, head_seq = GENESIS, 0, 0
        with self._sf() as db:
            for r in db.scalars(select(AuditRecord).order_by(AuditRecord.seq)):
                bad = None
                if r.seq != count + 1:
                    bad = "sequence gap (record deleted or inserted)"
                elif r.prev_hash != prev:
                    bad = "chain link broken"
                elif not hmac.compare_digest(r.hash, self._mac(r.prev_hash, {k: getattr(r, k) for k in _FIELDS})):
                    bad = "record content or hash modified"
                if bad:
                    return {"valid": False, "checked": count, "first_bad_seq": r.seq,
                            "reason": bad, "head_seq": None, "head_hash": None}
                prev, count, head_seq = r.hash, count + 1, r.seq
        return {"valid": True, "checked": count, "first_bad_seq": None, "reason": None,
                "head_seq": head_seq, "head_hash": prev if count else None}

    def list(self, limit: int = 100, before_seq: int | None = None) -> list[AuditRecord]:
        q = select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(limit)
        if before_seq:
            q = q.where(AuditRecord.seq < before_seq)
        with self._sf() as db:
            return list(db.scalars(q))


class BoundAudit:
    """AuditLog bound to the current request's client IP."""
    def __init__(self, log: AuditLog, ip: str | None):
        self._log, self._ip = log, ip

    def record(self, action: str, actor_id: str | None = None,
               target_id: str | None = None, **detail) -> None:
        self._log.record(action, actor_id, target_id, detail, self._ip)
