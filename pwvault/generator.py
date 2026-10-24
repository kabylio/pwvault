"""Cryptographically secure password generator (uses `secrets`, not `random`)."""
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password(length: int = 20, lower: bool = True, upper: bool = True,
                      digits: bool = True, symbols: bool = True) -> str:
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("select at least one character class")
    if length < 8:
        raise ValueError("length must be at least 8")

    # Guarantee one character from every selected class, then fill the rest.
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
