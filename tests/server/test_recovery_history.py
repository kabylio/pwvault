"""Regression coverage for encrypted history and account recovery."""
import base64
import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from pwvault import crypto, sharing
from pwvault.remote import RemoteError, RemoteVault, _b64e, derive_keys
from pwvault_server import security
from pwvault_server.db import PasskeyCredential, User
from .conftest import EMAIL, FAST, MASTER


def _hkdf(key: bytes, salt: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=label).derive(key)


def test_history_is_private_restorable_and_bounded(alice, bob):
    entry_id = alice.add_entry("history.example", "alice", "version zero")
    original = alice._req("GET", f"/entries/{entry_id}")
    for i in range(12):
        alice.update_entry(entry_id, password=f"version {i + 1}")

    history = alice._req("GET", f"/entries/{entry_id}/history")
    assert len(history) == 10
    assert history[0]["version"] == 12
    assert history[-1]["version"] == 3
    with pytest.raises(RemoteError) as error:
        bob._req("GET", f"/entries/{entry_id}/history")
    assert error.value.status == 404

    current = alice.get_entry(entry_id)
    alice._req("PUT", f"/entries/{entry_id}", json={
        "blob": original["blob"], "version": current.version,
    })
    assert alice.get_entry(entry_id).password == "version zero"


def test_recovery_options_do_not_reveal_account_or_recovery_state(http, alice):
    unknown = http.post("/auth/recovery/options", json={"email": "nobody@example.com"})
    unconfigured = http.post("/auth/recovery/options", json={"email": EMAIL})
    assert unknown.status_code == unconfigured.status_code == 200
    assert {k: len(v or "") for k, v in unknown.json().items()} == \
           {k: len(v or "") for k, v in unconfigured.json().items()}


def test_recovery_rewraps_vault_and_sharing_private_key(http, alice):
    recovery_secret, recovery_salt = secrets.token_bytes(32), secrets.token_bytes(16)
    recovery_enc = _hkdf(recovery_secret, recovery_salt, b"pwvault:recovery:v1:enc")
    recovery_auth = _hkdf(recovery_secret, recovery_salt, b"pwvault:recovery:v1:auth")
    _, current_auth = derive_keys(MASTER, alice._salt, FAST)
    setup = alice._req("POST", "/auth/recovery/setup", json={
        "auth_key": _b64e(current_auth),
        "recovery_auth_key": _b64e(recovery_auth),
        "recovery_salt": _b64e(recovery_salt),
        "recovery_wrapped_key": _b64e(crypto.encrypt(
            recovery_enc, alice._vault_key, b"pwvault:recovery:v1:vault-key")),
        "recovery_wrapped_private_key": _b64e(crypto.encrypt(
            recovery_enc, alice._priv, sharing.PRIV_AAD)),
    })
    assert setup == {"ok": True}

    options = http.post("/auth/recovery/options", json={"email": EMAIL}).json()
    assert len(base64.b64decode(options["recovery_wrapped_key"])) == 60
    assert len(base64.b64decode(options["recovery_wrapped_private_key"])) == 60
    unknown = http.post("/auth/recovery/options", json={"email": "nobody@example.com"}).json()
    assert {k: len(v or "") for k, v in options.items()} == \
           {k: len(v or "") for k, v in unknown.items()}

    new_password, new_salt = "a new, longer recovery password", secrets.token_bytes(16)
    new_enc, new_auth = derive_keys(new_password, new_salt, FAST)
    result = http.post("/auth/recovery/complete", json={
        "email": EMAIL,
        "recovery_auth_key": _b64e(recovery_auth),
        "new_auth_key": _b64e(new_auth),
        "new_salt": _b64e(new_salt),
        "new_kdf": {"time_cost": FAST.time_cost, "memory_cost_kib": FAST.memory_cost_kib,
                    "parallelism": FAST.parallelism},
        "new_wrapped_key": _b64e(crypto.encrypt(new_enc, alice._vault_key,
                                                   b"pwvault:remote-vault-key:v1")),
        "new_wrapped_private_key": _b64e(crypto.encrypt(new_enc, alice._priv, sharing.PRIV_AAD)),
    })
    assert result.status_code == 200
    recovered = RemoteVault.login(http, EMAIL, new_password)
    assert recovered._pub == alice._pub


def test_passkey_only_account_requires_step_up_for_security_changes(http, alice):
    credential_id = "stub-passkey-id"
    _, auth_key = derive_keys(MASTER, alice._salt, FAST)
    auth = _b64e(auth_key)
    first_registration = alice._req("POST", "/auth/passkeys/registration-options",
                                    json={"auth_key": auth})
    assert first_registration["challenge_id"]
    assert first_registration["options"]["rp"]["id"] == "localhost"
    with http.app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        db.add(PasskeyCredential(credential_id=credential_id, user_id=user.id,
            public_key=b"stub-public-key", sign_count=0, name="Test device",
            created_at=security.utcnow()))
        db.commit()
    def needs_factor(call):
        with pytest.raises(RemoteError) as error:
            call()
        assert error.value.status == 401
        assert error.value.detail == "otp_required"

    needs_factor(lambda: alice._req("POST", "/auth/passkeys/registration-options",
                                     json={"auth_key": auth}))
    needs_factor(lambda: alice._req("POST", "/auth/recovery/setup", json={
        "auth_key": auth, "recovery_auth_key": _b64e(secrets.token_bytes(32)),
        "recovery_salt": _b64e(secrets.token_bytes(16)),
        "recovery_wrapped_key": _b64e(secrets.token_bytes(28)),
        "recovery_wrapped_private_key": _b64e(secrets.token_bytes(28)),
    }))
    needs_factor(lambda: alice._req("POST", "/auth/2fa/setup", json={"auth_key": auth}))
    needs_factor(lambda: alice._req("DELETE", f"/auth/passkeys/{credential_id}",
                                     json={"auth_key": auth}))

    _, login_auth = derive_keys(MASTER, alice._salt, FAST)
    rejected = http.post("/auth/login", json={"email": EMAIL,
        "auth_key": _b64e(login_auth), "otp": "123456"})
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "Invalid credentials"

