import string

import pytest
from cryptography.fernet import Fernet

from pwvault.generator import SYMBOLS, generate_password
from pwvault.legacy import read_legacy


def test_generator_contains_every_class():
    for _ in range(50):
        pw = generate_password(12)
        assert len(pw) == 12
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_generator_validation():
    with pytest.raises(ValueError):
        generate_password(4)
    with pytest.raises(ValueError):
        generate_password(lower=False, upper=False, digits=False, symbols=False)


def test_generator_is_not_constant():
    assert len({generate_password() for _ in range(20)}) == 20


def test_legacy_import_roundtrip(tmp_path):
    key = Fernet.generate_key()
    f = Fernet(key)
    (tmp_path / "k.key").write_bytes(key)
    lines = [f"email:{f.encrypt(b'one').decode()}",
             "",
             f"email:{f.encrypt(b'two').decode()}",   # later line wins
             f"yt:{f.encrypt(b'three').decode()}"]
    (tmp_path / "p.pass").write_text("\n".join(lines))
    assert read_legacy(tmp_path / "k.key", tmp_path / "p.pass") == {
        "email": "two", "yt": "three"}


def test_legacy_wrong_key(tmp_path):
    f = Fernet(Fernet.generate_key())
    (tmp_path / "k.key").write_bytes(Fernet.generate_key())
    (tmp_path / "p.pass").write_text("a:" + f.encrypt(b"x").decode())
    with pytest.raises(ValueError):
        read_legacy(tmp_path / "k.key", tmp_path / "p.pass")
