"""Import from the original prototype (Fernet key file + 'site:token' lines)."""
from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def read_legacy(key_path: str | Path, password_path: str | Path) -> dict[str, str]:
    """Return {site: password}. Later lines win, matching the old behaviour."""
    fernet = Fernet(Path(key_path).read_bytes().strip())
    result: dict[str, str] = {}
    for lineno, line in enumerate(
            Path(password_path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        site, sep, token = line.rpartition(":")
        if not sep:
            raise ValueError(f"line {lineno}: expected 'site:token'")
        try:
            result[site] = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise ValueError(
                f"line {lineno}: cannot decrypt (wrong key file?)") from None
    return result
