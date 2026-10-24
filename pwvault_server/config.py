"""Configuration. Secrets come from the environment, never from source code."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    jwt_secret: str                      # signs access tokens
    server_key: bytes                    # encrypts TOTP secrets at rest (32 bytes)
    database_url: str = "sqlite:///./pwvault_server.db"
    token_minutes: int = 15
    max_failed_attempts: int = 5
    lockout_minutes: int = 15
    # Minimum Argon2id cost a client may choose (OWASP floor: 19 MiB, t=2, p=1)
    min_time_cost: int = 2
    min_memory_kib: int = 19456
    min_parallelism: int = 1
    breach_check: bool = False    # off by default: a bank may forbid outbound calls
    hibp_url: str = "https://api.pwnedpasswords.com/range/"
    registration: str = "open"     # "open" (dev) or "invite" (recommended for production)
    admin_emails: tuple = ()      # accounts created with these emails become admins
    webauthn_rp_id: str = "localhost"
    webauthn_origin: str = "http://localhost:8000"

    def __post_init__(self) -> None:
        if len(self.jwt_secret) < 32:
            raise ValueError("PWVAULT_JWT_SECRET must be at least 32 characters")
        if self.registration not in ("open", "invite"):
            raise ValueError("PWVAULT_REGISTRATION must be 'open' or 'invite'")
        if len(self.server_key) != 32:
            raise ValueError("PWVAULT_SERVER_KEY must decode to exactly 32 bytes")
        if self.token_minutes < 1:
            raise ValueError("PWVAULT_TOKEN_MINUTES must be at least 1")
        if self.max_failed_attempts < 1 or self.lockout_minutes < 1:
            raise ValueError("login lockout attempts and duration must be at least 1")
        if (self.min_time_cost < 1 or self.min_memory_kib < 8
                or self.min_parallelism < 1):
            raise ValueError("minimum Argon2id parameters are invalid")
        if self.min_memory_kib < 8 * self.min_parallelism:
            raise ValueError("minimum Argon2id memory must be at least 8 times parallelism")
        if (self.min_time_cost > 10 or self.min_memory_kib > 524_288
                or self.min_parallelism > 16):
            raise ValueError("minimum Argon2id parameters exceed the supported maximum")
        origin = urlsplit(self.webauthn_origin)
        local_http = (origin.scheme == "http" and origin.hostname in ("localhost", "127.0.0.1", "::1"))
        if (not self.webauthn_rp_id or not origin.hostname or origin.path not in ("", "/")
                or origin.query or origin.fragment or origin.username or origin.password
                or (origin.scheme != "https" and not local_http)):
            raise ValueError("WebAuthn requires a RP ID and a secure HTTPS origin (HTTP is allowed only on localhost)")

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            secret = os.environ["PWVAULT_JWT_SECRET"]
            key = base64.b64decode(os.environ["PWVAULT_SERVER_KEY"], validate=True)
        except KeyError as exc:
            raise RuntimeError(
                f"Missing environment variable {exc}. "
                "Run `python scripts/gen_secrets.py` to generate them.") from None
        return cls(
            jwt_secret=secret,
            server_key=key,
            database_url=os.environ.get("PWVAULT_DATABASE_URL", cls.database_url),
            token_minutes=int(os.environ.get("PWVAULT_TOKEN_MINUTES", 15)),
            breach_check=os.environ.get("PWVAULT_BREACH_CHECK", "").lower() in ("1", "true", "yes"),
            hibp_url=os.environ.get("PWVAULT_HIBP_URL", cls.hibp_url),
            registration=os.environ.get("PWVAULT_REGISTRATION", "open").lower(),
            admin_emails=tuple(e.strip().lower() for e in
                               os.environ.get("PWVAULT_ADMIN_EMAILS", "").split(",") if e.strip()),
            webauthn_rp_id=os.environ.get("PWVAULT_WEBAUTHN_RP_ID", "localhost"),
            webauthn_origin=os.environ.get("PWVAULT_WEBAUTHN_ORIGIN", "http://localhost:8000"),
        )
