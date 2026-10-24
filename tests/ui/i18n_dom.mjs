// Runs the REAL i18n.js against the REAL index.html in a DOM (jsdom). Prints JSON of observations.
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
const S = new URL('../../pwvault_server/static/', import.meta.url);
const dom = new JSDOM(readFileSync(new URL('index.html', S), 'utf8').replace(/<script[^>]*>.*?<\/script>/gs, ''),
  { pretendToBeVisual: true, url: 'http://localhost/' });
const { window } = dom;
for (const k of ['document', 'MutationObserver', 'localStorage']) globalThis[k] = window[k];
Object.defineProperty(globalThis, 'navigator', { value: { language: 'fr-FR' }, configurable: true });

await import(new URL('i18n.js', S));
const tick = () => new Promise((r) => setTimeout(r, 30));
const $ = (s) => document.querySelector(s), obs = {};
const snap = () => ({ dir: document.documentElement.dir, lang: document.documentElement.lang,
  go: $('#go').textContent, search: $('#search').placeholder, sel: $('#lang').value, tab: $('.tabs button').textContent });

obs.initial_fr = snap();
const b = document.createElement('button'); b.textContent = 'Delete'; document.body.append(b);       // built by app code
const li = document.createElement('li'); li.append(Object.assign(document.createElement('span'), { textContent: 'Copy password' }));
document.body.append(li);
$('#go').textContent = 'Create account';                                                                 // app changes text later
await tick();
obs.dynamic_fr = { added: b.textContent, nested: li.textContent, rewritten: $('#go').textContent };

$('#lang').value = 'ar'; $('#lang').dispatchEvent(new window.Event('change')); await tick();
obs.ar = { ...snap(), added: b.textContent, saved: localStorage.getItem('pwvault.lang') };

$('#lang').value = 'en'; $('#lang').dispatchEvent(new window.Event('change')); await tick();
obs.en = { ...snap(), added: b.textContent, nested: li.textContent };
$('#email').value = 'someone@example.dz'; obs.untouched = { email: $('#email').value, brand: document.querySelector('h1').textContent };
console.log(JSON.stringify(obs));
