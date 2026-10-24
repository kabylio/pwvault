import * as C from './crypto.js';

const $ = (s) => document.querySelector(s);
const form = $('#login'), status = $('#status'), matches = $('#matches');
let session = null;

function clearSession() {
  if (session?.encKey) session.encKey.fill(0);
  if (session?.vaultKey) session.vaultKey.fill(0);
  session = null;
}
addEventListener('pagehide', clearSession);

async function request(server, path, token, body) {
  const r = await fetch(new URL(path, server), {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `Server returned ${r.status}`);
  return data;
}

function originOf(value) {
  try {
    const u = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    return ['http:', 'https:'].includes(u.protocol) ? u.origin : null;
  } catch { return null; }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//.test(tab.url)) throw new Error('Open an ordinary HTTP or HTTPS website first.');
  return tab;
}

async function showMatches() {
  matches.replaceChildren();
  const tab = await activeTab(), pageOrigin = originOf(tab.url);
  const rows = await request(session.server, '/entries', session.token);
  const entries = await Promise.all(rows.map(async (row) => {
    try { return await C.open(session.vaultKey, row); } catch { return null; }
  }));
  const found = entries.filter((entry) => entry && originOf(entry.site) === pageOrigin);
  if (!found.length) { status.textContent = 'No login matches this exact website origin.'; return; }
  status.textContent = `${found.length} matching login${found.length === 1 ? '' : 's'}. Select one to fill.`;
  for (const entry of found) {
    const button = document.createElement('button'); button.className = 'match';
    const site = document.createElement('b'), username = document.createElement('span');
    site.textContent = entry.site; username.textContent = entry.username || '(no username)';
    button.append(site, username);
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          args: [entry.username || '', entry.password],
          func: (username, password) => {
            const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
            const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
            if (!passwords.length) throw new Error('No visible password field was found.');
            const field = passwords[0], form = field.form;
            if (username) {
              const candidates = [...(form || document).querySelectorAll('input:not([type]),input[type="text"],input[type="email"],input[autocomplete="username"]')]
                .filter((el) => visible(el) && !el.disabled && !el.readOnly);
              const userField = candidates.find((el) => el.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING) || candidates[0];
              if (userField) {
                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                setter.call(userField, username);
                userField.dispatchEvent(new Event('input', { bubbles: true }));
                userField.dispatchEvent(new Event('change', { bubbles: true }));
              }
            }
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
            setter.call(field, password);
            field.dispatchEvent(new Event('input', { bubbles: true }));
            field.dispatchEvent(new Event('change', { bubbles: true }));
          },
        });
        status.textContent = 'Filled the visible login form. Review it and submit the page yourself.';
      } catch (e) { status.textContent = e.message || 'Could not fill this page.'; button.disabled = false; }
    });
    matches.append(button);
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submit = form.querySelector('button'); submit.disabled = true;
  status.textContent = ''; matches.replaceChildren(); clearSession();
  try {
    const server = new URL($('#server').value.trim());
    if (!['http:', 'https:'].includes(server.protocol) || server.username || server.password || server.search || server.hash)
      throw new Error('Enter only the server origin, such as https://vault.example.');
    const origin = server.origin;
    const permission = `${origin}/*`;
    if (!await chrome.permissions.contains({ origins: [permission] }) &&
        !await chrome.permissions.request({ origins: [permission] })) throw new Error('Permission to contact this server was not granted.');
    const email = $('#email').value.trim().toLowerCase(), password = $('#password').value;
    const pre = await request(origin, '/auth/prelogin', null, { email });
    const salt = C.b64d(pre.salt), kdf = pre.kdf;
    const { encKey, authKey } = await C.deriveKeys(window.hashwasm.argon2id, password, salt, kdf);
    const body = { email, auth_key: C.b64e(authKey) }, factor = $('#factor').value.trim();
    if (factor) body[/^\d{6}$/.test(factor) ? 'otp' : 'recovery_code'] = factor;
    let login;
    try { login = await request(origin, '/auth/login', null, body); }
    catch (e) {
      if (e.message === 'otp_required') {
        $('#factor-row').hidden = false;
        throw new Error('Enter your authenticator or recovery code above, then unlock again.');
      }
      throw e;
    }
    const vaultKey = await C.decrypt(encKey, C.b64d(login.wrapped_key), C.WRAP_AAD);
    session = { server: origin, token: login.access_token, encKey, vaultKey };
    $('#password').value = ''; $('#factor').value = ''; $('#factor-row').hidden = true;
    form.hidden = true; $('#session-controls').hidden = false;
    await showMatches();
  } catch (e) { status.textContent = e.message || 'Could not unlock PWVault.'; }
  finally { submit.disabled = false; }
});

chrome.storage.local.get({ server: 'http://127.0.0.1:8012' }, ({ server }) => { $('#server').value = server; });
$('#server').addEventListener('change', () => chrome.storage.local.set({ server: $('#server').value.trim() }));

$('#lockExtension').addEventListener('click', () => {
  clearSession();
  form.hidden = false; $('#session-controls').hidden = true; matches.replaceChildren();
  status.textContent = 'PWVault extension locked.';
});
