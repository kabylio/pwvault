import pyotp
import pytest

from pwvault.remote import OtpRequired, RemoteError, RemoteVault
from pwvault_server import security
from .conftest import EMAIL, MASTER

T0 = 1_800_000_000


@pytest.fixture
def clock(monkeypatch):
    """Controllable clock so TOTP tests are deterministic."""
    state = {"now": T0}
    monkeypatch.setattr(security, "current_time", lambda: state["now"])
    return state


@pytest.fixture
def twofa(alice, clock):
    secret, uri = alice.setup_2fa(MASTER)
    totp = pyotp.TOTP(secret)
    codes = alice.enable_2fa(totp.at(T0))
    return totp, codes


def test_setup_returns_standard_otpauth_uri(alice):
    secret, uri = alice.setup_2fa(MASTER)
    assert uri.startswith("otpauth://totp/") and secret in uri and "pwvault" in uri


def test_setup_requires_master_password_confirmation(alice):
    with pytest.raises(RemoteError) as e:
        alice.setup_2fa("wrong master password!")
    assert e.value.status == 403
    assert alice.me()["totp_enabled"] is False
    with pytest.raises(RemoteError) as e:
        alice._req("POST", "/auth/2fa/setup")  # a bearer token by itself is insufficient
    assert e.value.status == 422


def test_enable_with_wrong_code_fails(alice, clock):
    secret, _ = alice.setup_2fa(MASTER)
    with pytest.raises(RemoteError) as e:
        alice.enable_2fa("000000" if pyotp.TOTP(secret).at(T0) != "000000" else "111111")
    assert e.value.status == 400
    assert alice.me()["totp_enabled"] is False


def test_enable_requires_setup_first(alice):
    with pytest.raises(RemoteError) as e:
        alice.enable_2fa("123456")
    assert e.value.status == 409


def test_login_requires_otp_once_enabled(http, twofa, clock):
    totp, _ = twofa
    with pytest.raises(OtpRequired):
        RemoteVault.login(http, EMAIL, MASTER)
    clock["now"] = T0 + 30
    session = RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 30))
    assert session.me()["totp_enabled"] is True


def test_wrong_otp_rejected(http, twofa, clock):
    clock["now"] = T0 + 30
    with pytest.raises(RemoteError) as e:
        RemoteVault.login(http, EMAIL, MASTER, otp="000000")
    assert e.value.status == 401 and e.value.detail != "otp_required"


def test_otp_cannot_be_replayed(http, twofa, clock):
    totp, _ = twofa
    clock["now"] = T0 + 30
    code = totp.at(T0 + 30)
    RemoteVault.login(http, EMAIL, MASTER, otp=code)
    with pytest.raises(RemoteError):                       # same code again
        RemoteVault.login(http, EMAIL, MASTER, otp=code)
    clock["now"] = T0 + 60                                 # next window works
    assert RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 60))


def test_code_used_to_enable_cannot_be_reused_to_login(http, twofa, clock):
    totp, _ = twofa
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0))


def test_old_codes_outside_window_rejected(http, twofa, clock):
    totp, _ = twofa
    clock["now"] = T0 + 300
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 30 - 120))


def test_correct_otp_but_wrong_password_rejected(http, twofa, clock):
    totp, _ = twofa
    clock["now"] = T0 + 30
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, "wrong master password!", otp=totp.at(T0 + 30))


def test_recovery_codes_work_exactly_once(http, twofa):
    _, codes = twofa
    assert len(codes) == 8 and len(set(codes)) == 8
    assert RemoteVault.login(http, EMAIL, MASTER, recovery_code=codes[0])
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, MASTER, recovery_code=codes[0])
    assert RemoteVault.login(http, EMAIL, MASTER, recovery_code=codes[1])


def test_disable_requires_password_and_second_factor(http, twofa, clock):
    totp, codes = twofa
    clock["now"] = T0 + 30
    session = RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 30))
    # stolen token alone is not enough: wrong password
    with pytest.raises(RemoteError):
        session.disable_2fa("wrong master password!", recovery_code=codes[0])
    session.disable_2fa(MASTER, recovery_code=codes[1])
    assert session.me()["totp_enabled"] is False
    assert RemoteVault.login(http, EMAIL, MASTER)        # no OTP needed anymore


def test_change_master_password_requires_second_factor(http, twofa, clock):
    totp, _ = twofa
    clock["now"] = T0 + 30
    session = RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 30))
    new_password = "a brand new master password"
    with pytest.raises(OtpRequired):
        session.change_master_password(MASTER, new_password)
    clock["now"] = T0 + 60
    session.change_master_password(MASTER, new_password, otp=totp.at(T0 + 60))
    clock["now"] = T0 + 90
    with pytest.raises(RemoteError):
        RemoteVault.login(http, EMAIL, MASTER, otp=totp.at(T0 + 90))
    assert RemoteVault.login(http, EMAIL, new_password, otp=totp.at(T0 + 90))


def test_totp_secret_is_encrypted_at_rest(http, alice, settings):
    secret, _ = alice.setup_2fa(MASTER)
    raw = open(settings.database_url.removeprefix("sqlite:///"), "rb").read()
    assert secret.encode() not in raw
