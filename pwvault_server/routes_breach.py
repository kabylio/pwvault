"""k-anonymity proxy for Pwned Passwords. The server sees only a 5-char hash
prefix (never a password or full hash) and hides the user's IP from HIBP."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.responses import PlainTextResponse

from .config import Settings
from .db import User
from .deps import current_user, get_settings

router = APIRouter(prefix="/breach", tags=["breach"])


@router.get("/status")
def status(_: User = Depends(current_user), s: Settings = Depends(get_settings)):
    return {"enabled": s.breach_check}


@router.get("/range/{prefix}", response_class=PlainTextResponse)
def hibp_range(request: Request, prefix: str = Path(pattern=r"^[0-9A-Fa-f]{5}$"),
               _: User = Depends(current_user), s: Settings = Depends(get_settings)):
    if not s.breach_check:
        raise HTTPException(503, "Breach check is disabled on this server")
    try:
        resp = request.app.state.hibp.get(
            s.hibp_url + prefix.upper(),
            headers={"Add-Padding": "true", "User-Agent": "pwvault"})
        resp.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(502, "Breach service unavailable") from None
    return PlainTextResponse(resp.text)
