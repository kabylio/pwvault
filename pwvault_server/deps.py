"""FastAPI dependencies."""
from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import security
from .config import Settings
from .db import User

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request):
    with request.app.state.session_factory() as session:
        yield session


def unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    if creds is None:
        raise unauthorized()
    try:
        claims = security.decode_token(settings, creds.credentials)
    except jwt.PyJWTError:
        raise unauthorized("Invalid or expired token") from None
    user = db.get(User, claims["sub"])
    # token_version lets us revoke every token at once (e.g. password change)
    if user is None or user.disabled or user.token_version != claims.get("tv"):
        raise unauthorized("Invalid or expired token")
    return user


def get_audit(request: Request):
    from .audit import BoundAudit
    return BoundAudit(request.app.state.audit,
                      request.client.host if request.client else None)


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return user
