"""Application factory."""
from __future__ import annotations

from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from . import routes_admin, routes_auth, routes_breach, routes_entries, routes_passkeys, routes_recovery, routes_vaults
from .config import Settings
from .audit import AuditLog
from .db import Base, make_engine, migrate


# Strict CSP for the web UI: only our own files, no inline script, no third parties.
UI_CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
          "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
          "form-action 'self'; frame-ancestors 'none'")


def create_app(settings: Settings | None = None, hibp_transport=None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    migrate(engine)

    app = FastAPI(title="pwvault API", version="1.1.0",
                  description="Zero-knowledge password vault: the server only "
                              "ever stores ciphertext.")
    app.state.settings = settings
    app.state.session_factory = sessionmaker(engine, expire_on_commit=False)
    app.state.hibp = httpx.Client(timeout=5.0, transport=hibp_transport)
    app.state.audit = AuditLog(app.state.session_factory, settings.server_key)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/app"):
            response.headers["Content-Security-Policy"] = UI_CSP
        return response

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/app/")

    app.mount("/app", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")
    app.include_router(routes_auth.router)
    app.include_router(routes_passkeys.router)
    app.include_router(routes_recovery.router)
    app.include_router(routes_entries.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_breach.router)
    app.include_router(routes_vaults.router)
    return app
