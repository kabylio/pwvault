import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "pwvault_server" / "static"
SAME_IN_ALL = {"Admin", "Site", "Notes", "Administration"}          # identical or international words
LANG_NAMES = {"English", "Français", "العربية"}


@pytest.fixture(scope="module")
def strings():
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    out = subprocess.run(["node", "-e", "import('./strings.js').then(m=>console.log(JSON.stringify(m.default)))"],
                         cwd=STATIC, capture_output=True, text=True, check=True, timeout=30)
    return json.loads(out.stdout)


def test_french_and_arabic_cover_exactly_the_same_phrases(strings):
    assert set(strings["fr"]) == set(strings["ar"])


def test_no_empty_or_untranslated_entries(strings):
    for lang in ("fr", "ar"):
        for en, tr in strings[lang].items():
            assert tr.strip(), f"{lang}: empty translation for {en!r}"
            if en not in SAME_IN_ALL and not en.startswith(("+ ", "🔒")):
                assert tr != en, f"{lang}: {en!r} is not translated"


def test_arabic_entries_are_written_in_arabic_script(strings):
    for en, tr in strings["ar"].items():
        if en not in SAME_IN_ALL:
            assert re.search(r"[\u0600-\u06FF]", tr), f"{en!r} -> {tr!r}"


def test_placeholders_and_symbols_survive_translation(strings):
    for lang in ("fr", "ar"):
        for en, tr in strings[lang].items():
            for mark in ("…", "✅", "🔒"):
                assert (mark in en) == (mark in tr), (lang, en, tr)
            assert en.startswith("+ ") == tr.startswith("+ "), (lang, en, tr)


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.texts, self.skip = [], 0
    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style")
        for k, v in attrs:
            if k in ("placeholder", "aria-label", "title") and v:
                self.texts.append(v)
    def handle_endtag(self, tag):
        self.skip -= tag in ("script", "style")
    def handle_data(self, data):
        if not self.skip and data.strip():
            self.texts.append(data.strip())


def test_every_visible_string_in_the_html_has_a_translation(strings):
    parser = _Text(); parser.feed((STATIC / "index.html").read_text())
    ignore = LANG_NAMES | {"pwvault", "🔐 pwvault", "2FA", "XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX",
                           "6-digit code", "colleague@example.dz"}
    missing = sorted({t for t in parser.texts if t not in strings["fr"] and t not in ignore})
    assert missing == [], f"untranslated static strings: {missing}"


def test_language_switcher_and_rtl_wiring():
    html, css = (STATIC / "index.html").read_text(), (STATIC / "app.css").read_text()
    assert re.search(r'<select id="lang"[^>]*>.*value="fr".*value="ar"', html, re.S)
    assert "[dir=rtl]" in css and "direction:ltr" in css           # secrets and fingerprints stay left-to-right
    js = (STATIC / "i18n.js").read_text()
    assert "documentElement.dir" in js and "innerHTML" not in js


@pytest.mark.skipif(shutil.which("node") is None or not (Path(__file__).resolve().parents[1] / "ui" / "node_modules" / "jsdom").exists(),
                    reason="needs node and `npm install` in tests/ui")
def test_translation_engine_in_a_real_dom():
    out = subprocess.run(["node", str(Path(__file__).resolve().parents[1] / "ui" / "i18n_dom.mjs")],
                         capture_output=True, text=True, check=True, timeout=60)
    o = json.loads(out.stdout)
    fr = o["initial_fr"]                                  # browser language French -> starts in French
    assert (fr["lang"], fr["dir"], fr["sel"]) == ("fr", "ltr", "fr")
    assert fr["go"] == "Se connecter" and fr["search"] == "Rechercher…" and fr["tab"] == "Se connecter"
    assert o["dynamic_fr"] == {"added": "Supprimer", "nested": "Copier le mot de passe", "rewritten": "Créer un compte"}
    ar = o["ar"]                                          # switching to Arabic flips the layout direction
    assert (ar["lang"], ar["dir"], ar["saved"]) == ("ar", "rtl", "ar")
    assert ar["go"] == "إنشاء حساب" and ar["added"] == "حذف" and ar["search"] == "بحث…"
    en = o["en"]                                          # and back: original English fully restored
    assert (en["lang"], en["dir"]) == ("en", "ltr")
    assert (en["go"], en["search"], en["added"], en["nested"]) == ("Create account", "Search…", "Delete", "Copy password")
    assert o["untouched"] == {"email": "someone@example.dz", "brand": "🔐 pwvault"}   # user data and brand never translated
