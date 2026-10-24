import json
import shutil
import subprocess
from pathlib import Path

import pytest

from pwvault.remote import _b64d, _b64e, derive_keys
from pwvault.crypto import KdfParams
from pwvault.remote import RemoteVault
from .conftest import EMAIL, FAST, MASTER

ROOT = Path(__file__).resolve().parents[2]


def test_ui_is_served_with_strict_csp(http):
    r = http.get("/app/")
    assert r.status_code == 200 and "pwvault" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self' 'wasm-unsafe-eval'" in csp and "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    assert http.get("/app/app.js").status_code == 200
    assert http.get("/", follow_redirects=False).status_code in (302, 307)


def test_ui_has_no_inline_script_or_external_resources(http):
    html = http.get("/app/").text
    assert "<script>" not in html
    assert "http://" not in html and "https://" not in html


def test_api_responses_are_not_cached(http):
    assert http.get("/health").headers["cache-control"] == "no-store"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_browser_crypto_is_byte_compatible_with_python_client(http, alice):
    eid = alice.add_entry("python.example", "pyuser", "pa55-ÿ-密码", "py notes")
    row = alice._req("GET", f"/entries/{eid}")
    pre = http.post("/auth/prelogin", json={"email": EMAIL}).json()
    _, auth_key = derive_keys(MASTER, _b64d(pre["salt"]), FAST)
    wrapped = http.post("/auth/login", json={"email": EMAIL, "auth_key": _b64e(auth_key)}).json()["wrapped_key"]

    from pwvault import sharing
    sk, pk = sharing.generate_keypair()
    job = {"password": MASTER, "salt": pre["salt"], "kdf": pre["kdf"], "wrapped_key": wrapped, "row": row,
           "share": {"priv": _b64e(sk), "pub": _b64e(pk), "aad": "x",
                     "wrapped": _b64e(sharing.wrap_for(pk, b"from-python-vault-key", sharing.key_aad("v", "u", 3)))}}
    out = subprocess.run(["node", str(ROOT / "tests/ui/interop.mjs")], input=json.dumps(job),
                         capture_output=True, text=True, check=True, timeout=60)
    res = json.loads(out.stdout)

    assert res["authKey"] == _b64e(auth_key)                      # same KDF + HKDF
    assert (res["opened"]["site"], res["opened"]["password"], res["opened"]["notes"]) == \
           ("python.example", "pa55-ÿ-密码", "py notes")            # JS opens Python's entry
    js_row = {"id": res["id"], "blob": res["sealed"], "version": 1,
              "created_at": "", "updated_at": ""}
    e = alice._open(js_row)                                        # Python opens JS's entry
    assert (e.site, e.username, e.password) == ("from-js.example", "jsuser", "pässwörd-日本")
    assert len(res["pw"]) == 24 and res["strong"] >= 3 and res["weak"] <= 1
    # sharing: JS opens Python's sealed key; Python opens JS's; keys/fingerprints agree
    sh = res["share"]
    assert _b64d(sh["unwrapped"]) == b"from-python-vault-key"
    assert _b64d(sh["pubFromPriv"]) == pk and sh["fp"] == sharing.fingerprint(pk)
    assert sharing.public_from_private(_b64d(sh["jsPriv"])) == _b64d(sh["jsPub"])
    assert sharing.unwrap(sk, _b64d(sh["wrappedForPy"]), sharing.key_aad("v", "u", 3)) == b"from-js-vault-key"
    # breach helpers agree with the Python implementation
    from pwvault import breach
    assert (res["sha"]["prefix"], res["sha"]["suffix"]) == breach.split_hash("password")
    assert res["count"] == 9545824


def test_every_element_id_used_by_app_js_exists_in_the_html():
    """Static wiring check: a typo'd id would silently break a button."""
    import re
    static = ROOT / "pwvault_server" / "static"
    html, js = (static / "index.html").read_text(), (static / "app.js").read_text()
    html_ids = re.findall(r'\bid="([^"]+)"', html)
    assert len(html_ids) == len(set(html_ids)), "duplicate ids in index.html"
    used = set(re.findall(r"\$\('#([A-Za-z0-9_]+)'\)", js))
    used |= set(re.findall(r"'#([A-Za-z0-9_]+)'", js))        # ids listed in arrays
    assert used - set(html_ids) == set()


def test_ui_never_uses_innerhtml_or_eval():
    static = ROOT / "pwvault_server" / "static"
    for name in ("app.js", "crypto.js"):
        code = (static / name).read_text()
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert banned not in code, f"{name} uses {banned}"
