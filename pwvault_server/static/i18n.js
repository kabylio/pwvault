// Tiny i18n: the English UI text is the key. A MutationObserver translates text and placeholders
// as they appear, so screens built by JavaScript are covered too. English needs no dictionary.
import D from './strings.js';

const ATTRS = ['placeholder', 'aria-label', 'title'], orig = new WeakMap();
let lang = 'en';
const tx = (s) => (lang === 'en' ? s : D[lang][s] ?? s);

function node(n) {
  if (n.nodeType === 3) {
    const raw = orig.has(n) ? orig.get(n) : n.nodeValue, key = raw.trim();
    if (!Object.hasOwn(D.fr, key)) return;
    orig.set(n, raw);
    const next = raw.replace(key, tx(key));
    if (n.nodeValue !== next) n.nodeValue = next;      // only write on change: no observer loop
  } else if (n.nodeType === 1) {
    for (const a of ATTRS) {
      const v = n.getAttribute(a); if (v === null) continue;
      const store = (n._en ??= {}); if (!(a in store)) store[a] = v;
      const next = Object.hasOwn(D.fr, store[a]) ? tx(store[a]) : v;
      if (v !== next) n.setAttribute(a, next);
    }
  }
}
const walk = (n) => { node(n); n.childNodes?.forEach(walk); };

export function setLang(l) {
  lang = ['fr', 'ar'].includes(l) ? l : 'en';
  document.documentElement.lang = lang; document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  try { localStorage.setItem('pwvault.lang', lang); } catch { /* storage may be blocked */ }
  const sel = document.getElementById('lang'); if (sel) sel.value = lang;
  walk(document.body);
}
new MutationObserver((ms) => ms.forEach((m) => { m.addedNodes.forEach(walk); if (m.type === 'characterData') node(m.target); }))
  .observe(document.body, { childList: true, subtree: true, characterData: true });
document.getElementById('lang').onchange = (e) => setLang(e.target.value);
let saved = null; try { saved = localStorage.getItem('pwvault.lang'); } catch { /* ignore */ }
setLang(saved || (navigator.language || 'en').slice(0, 2));
