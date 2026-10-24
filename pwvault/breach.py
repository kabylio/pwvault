"""Have I Been Pwned 'Pwned Passwords' k-anonymity helpers.

Only the first 5 hex chars of SHA-1(password) are ever sent anywhere; the
full hash and the password stay local. (SHA-1 is used purely because the HIBP
API is defined that way. It is not used to protect anything.)
"""
import hashlib


def split_hash(password: str) -> tuple[str, str]:
    h = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return h[:5], h[5:]


def count_in_range(range_text: str, suffix: str) -> int:
    """Occurrences of `suffix` in an HIBP range response (0 = not found).
    Padding rows returned by the API have a count of 0, so they never match."""
    for line in range_text.splitlines():
        sfx, _, count = line.strip().partition(":")
        if sfx.upper() == suffix.upper():
            return int(count or 0)
    return 0
