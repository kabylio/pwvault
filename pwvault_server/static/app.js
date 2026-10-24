import * as C from './crypto.js';
import './i18n.js';
const $ = (s) => document.querySelector(s);
const argon = (o) => window.hashwasm.argon2id(o);
const KDF = { time_cost: 3, memory_cost_kib: 65536, parallelism: 4 };
const IDLE_MS = 5 * 60 * 1000, CLIP_MS = 20 * 1000;
let S = null, pending = null, mode = 'login', entries = [], editing = null, idle = null, ctx = null, vaults = [], pendingImport = [], activeAttachments = [], customRows = [];
let registrationPolicyLoaded = false, registrationPolicyFailed = false, invitationRequired = false;

const toast = (m) => { const t = $('#toast'); t.textContent = m; t.classList.add('on'); setTimeout(() => t.classList.remove('on'), 2500); };
const show = (unlocked) => { $('#auth').hidden = unlocked; $('#vault').hidden = !unlocked; $('#tools').hidden = !unlocked; $('#who').textContent = unlocked ? S.email : ''; };
const meter = (el, pw) => { const s = C.strength(pw); el.dataset.score = s.score; el.querySelector('small').textContent = s.label; };

async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', ...(S ? { Authorization: 'Bearer ' + S.token } : {}) },
    body: body ? JSON.stringify(body) : undefined });
  const d = r.status === 204 ? null : await r.json().catch(() => ({}));
  if (!r.ok) {
    const detail = typeof d.detail === 'string' ? d.detail : 'Invalid input';
    if (r.status === 401 && S && ['Invalid or expired token', 'Not authenticated'].includes(detail)) lock('Session expired, please sign in again.');
    throw Object.assign(new Error(detail), { status: r.status, detail });
  }
  return d;
}

// ---- locking: drop every key and decrypted value from memory ----
function lock(msg) {
  // Best-effort wipe typed key buffers before dropping references.
  for (const key of [S?.vaultKey, S?.priv, pending?.encKey, pending?.authKey, ctx?.key,
    ...vaults.map((v) => v.key)]) if (key instanceof Uint8Array) key.fill(0);
  S = null; pending = null; entries = []; editing = null; ctx = null; vaults = []; pendingImport = []; activeAttachments = []; customRows = []; clearTimeout(idle);
  $('#list').replaceChildren(); $('#master').value = $('#confirm').value = $('#otp').value = '';
  // Closing a dialog does not remove its DOM. Clear decrypted fields and
  // rendered 2FA material as well, including when the idle timer locks us.
  ['#fSite', '#fUser', '#fPass', '#fNotes', '#search', '#backupPass', '#backupConfirm', '#importPass', '#importFile', '#setupRecoveryPassword', '#setupRecoveryFactor', '#passkeyPassword', '#passkeyFactor', '#recoveryEmail', '#recoveryKey', '#recoveryNew', '#recoveryConfirm', '#recoveryFactor'].forEach((s) => { if ($(s)) $(s).value = ''; });
  ['#breachRes', '#entryErr', '#twofaBody', '#healthBody', '#adminBody', '#membersBody', '#passkeyList', '#historyBody', '#customFields', '#attachmentList']
    .forEach((s) => $(s).replaceChildren());
  $('#passkeyName').value = $('#passkeyStatus').textContent = '';
  $('#newRecoveryKey').textContent = $('#recoverySetupStatus').textContent = '';
  ['#meter', '#meter2'].forEach((s) => { $(s).dataset.score = '0'; $(s).querySelector('small').textContent = ''; });
  setPwVisible(false);
  ['#dlgEntry', '#dlg2fa', '#dlgHealth', '#dlgAdmin', '#dlgMembers', '#dlgBackup', '#dlgPasskeys', '#dlgHistory', '#dlgRecoverySetup', '#dlgRecovery'].forEach((d) => $(d).close?.()); $('#btnAdmin').hidden = true; setMode('login'); show(false);
  $('#showPw').checked = false; ['#master', '#confirm'].forEach((s) => ($(s).type = 'password')); $('#ack').checked = false; $('#invite').value = '';
  const n = $('#notice'); n.hidden = !msg; n.textContent = msg || '';
}
const bump = () => { if (!S) return; clearTimeout(idle); idle = setTimeout(() => lock('Locked after 5 minutes of inactivity.'), IDLE_MS); };
['click', 'keydown', 'mousemove', 'touchstart'].forEach((ev) => addEventListener(ev, bump, { passive: true }));
$('#btnLock').onclick = () => lock('Locked.');

// ---- auth ----
function setMode(m) {
  if (mode === 'register' && m !== 'register') {
    $('#invite').value = ''; $('#confirm').value = ''; $('#ack').checked = false;
  }
  mode = m; pending = null;
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('on', b.dataset.mode === m));
  ['#confirmRow', '#meter', '#regHint', '#ackRow'].forEach((s) => ($(s).hidden = m !== 'register'));
  $('#inviteRow').hidden = m !== 'register' || !invitationRequired;
  $('#loginActions').hidden = m !== 'login';
  $('#go').disabled = m === 'register' && (!registrationPolicyLoaded || registrationPolicyFailed);
  $('#master').autocomplete = m === 'login' ? 'current-password' : 'new-password';
  $('#go').textContent = m === 'login' ? 'Sign in' : 'Create account';
  $('#err').textContent = m === 'register'
    ? registrationPolicyFailed ? 'Could not load registration requirements. Refresh the page and try again.'
      : !registrationPolicyLoaded ? 'Loading registration requirements...' : ''
    : '';
}
setMode('login');
document.querySelectorAll('.tabs button').forEach((b) => (b.onclick = () => setMode(b.dataset.mode)));
fetch('/auth/registration-policy', { cache: 'no-store' }).then((r) => {
  if (!r.ok) throw new Error('Could not load registration policy');
  return r.json();
}).then((policy) => {
  invitationRequired = policy.invite_required === true;
}).catch(() => {
  registrationPolicyFailed = true;
}).finally(() => {
  registrationPolicyLoaded = true;
  setMode(mode);
});
$('#master').oninput = () => mode === 'register' && meter($('#meter'), $('#master').value);

$('#authForm').onsubmit = async (ev) => {
  ev.preventDefault(); const go = $('#go'), err = $('#err'); err.textContent = ''; go.disabled = true;
  if (mode === 'register' && (!registrationPolicyLoaded || registrationPolicyFailed)) {
    err.textContent = 'Could not load registration requirements. Refresh the page and try again.';
    go.disabled = true; return;
  }
  const email = $('#email').value.trim().toLowerCase(), pw = $('#master').value;
  try {
    if (mode === 'register') {
      if (pw.length < 12) throw new Error('Master password must be at least 12 characters.');
      if (pw !== $('#confirm').value) throw new Error('Passwords do not match.');
      if (!$('#ack').checked) throw new Error('Please confirm that a recovery key must be set up in advance to recover vault access.');
      go.textContent = 'Deriving keys…';
      const salt = C.rand(16), { encKey, authKey } = await C.deriveKeys(argon, pw, salt, KDF);
      const wrapped = C.b64e(await C.encrypt(encKey, C.rand(32), C.WRAP_AAD));
      await api('POST', '/auth/register', { email, auth_key: C.b64e(authKey), salt: C.b64e(salt), kdf: KDF, wrapped_key: wrapped, invite_code: $('#invite').value.trim() || undefined });
    }
    if (!pending) {
      go.textContent = 'Deriving keys…';
      const pre = await api('POST', '/auth/prelogin', { email });
      const salt = C.b64d(pre.salt);
      pending = { email, salt, kdf: pre.kdf, ...(await C.deriveKeys(argon, pw, salt, pre.kdf)) };
    }
    const body = { email, auth_key: C.b64e(pending.authKey) }, code = $('#otp').value.trim();
    if (!$('#otpRow').hidden && code) body[/^\d{6}$/.test(code) ? 'otp' : 'recovery_code'] = code;
    let d;
    try { d = await api('POST', '/auth/login', body); }
    catch (e) { if (e.detail === 'otp_required') { $('#otpRow').hidden = false; $('#usePasskey').hidden = !navigator.credentials?.get; $('#otp').focus(); err.textContent = 'Enter your authenticator or recovery code, or use a passkey.'; return; } throw e; }
    await completeLogin(d, pending);
  } catch (e) { err.textContent = e.status === 429 ? 'Too many attempts. Try again later.' : e.status === 401 ? 'Invalid credentials.' : e.message; if (e.status) pending = null; }
  finally { go.disabled = false; go.textContent = mode === 'login' ? 'Sign in' : 'Create account'; }
};

async function completeLogin(d, material) {
  let vk;
  try { vk = await C.decrypt(material.encKey, C.b64d(d.wrapped_key), C.WRAP_AAD); }
  catch { throw new Error('Could not unlock the vault.'); }
  S = { email: material.email, token: d.access_token, vaultKey: vk, salt: material.salt, kdf: material.kdf };
  try { await initKeys(d, material.encKey); }
  catch (x) {
    S.vaultKey.fill(0); S.priv?.fill(0); S = null;
    throw x.name === 'NotSupportedError' ? new Error('This browser does not support X25519 (needed for sharing). Please update your browser.') : x;
  } finally { material.encKey?.fill(0); material.authKey?.fill(0); }
  pending = null;
  $('#master').value = $('#confirm').value = $('#otp').value = ''; $('#notice').hidden = true;
  const me = await api('GET', '/auth/me'); S.id = me.id; $('#btnAdmin').hidden = me.role !== 'admin';
  show(true); bump(); await loadVaults(); await load();
}

const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
const toB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
function webauthnJSON(credential) {
  if (credential.toJSON) return credential.toJSON();
  const response = credential.response;
  const data = { clientDataJSON: toB64url(response.clientDataJSON) };
  if (response.attestationObject) data.attestationObject = toB64url(response.attestationObject);
  if (response.authenticatorData) data.authenticatorData = toB64url(response.authenticatorData);
  if (response.signature) data.signature = toB64url(response.signature);
  if (response.userHandle) data.userHandle = toB64url(response.userHandle);
  return { id: credential.id, rawId: toB64url(credential.rawId), type: credential.type,
    response: data, clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment };
}
function publicKeyOptions(o) {
  const options = { ...o, challenge: fromB64url(o.challenge) };
  if (o.user) options.user = { ...o.user, id: fromB64url(o.user.id) };
  if (o.allowCredentials) options.allowCredentials = o.allowCredentials.map((c) => ({ ...c, id: fromB64url(c.id) }));
  if (o.excludeCredentials) options.excludeCredentials = o.excludeCredentials.map((c) => ({ ...c, id: fromB64url(c.id) }));
  return options;
}
async function secondFactorFields(authKey, value = '') {
  if (value) return { [/^\d{6}$/.test(value) ? 'otp' : 'recovery_code']: value };
  const rows = await api('GET', '/auth/passkeys');
  if (!rows.length) return {};
  if (!navigator.credentials?.get) throw new Error('Use an authenticator/recovery code or a browser that supports passkeys.');
  const ceremony = await api('POST', '/auth/passkeys/authentication-options',
    { email: S.email, auth_key: C.b64e(authKey) });
  const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions(ceremony.options) });
  if (!assertion) throw new Error('Passkey confirmation was cancelled.');
  return { passkey_challenge_id: ceremony.challenge_id, passkey_assertion: webauthnJSON(assertion) };
}
$('#usePasskey').onclick = async () => {
  const button = $('#usePasskey'), err = $('#err'); button.disabled = true; err.textContent = '';
  try {
    if (!pending) throw new Error('Enter your email and master password first.');
    const ceremony = await api('POST', '/auth/passkeys/authentication-options',
      { email: pending.email, auth_key: C.b64e(pending.authKey) });
    const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions(ceremony.options) });
    if (!assertion) throw new Error('Passkey authentication was cancelled.');
    const d = await api('POST', '/auth/login', { email: pending.email, auth_key: C.b64e(pending.authKey),
      passkey_challenge_id: ceremony.challenge_id, passkey_assertion: webauthnJSON(assertion) });
    await completeLogin(d, pending);
  } catch (e) { err.textContent = e.message || 'Passkey sign in failed.'; }
  finally { button.disabled = false; }
};

async function renderPasskeys() {
  const list = $('#passkeyList'); list.replaceChildren();
  const rows = await api('GET', '/auth/passkeys');
  if (!rows.length) { list.textContent = 'No passkeys registered.'; return; }
  for (const item of rows) {
    const row = document.createElement('div'); row.className = 'row';
    const name = document.createElement('span'); name.textContent = item.name;
    const remove = btn('Remove', async () => {
      if (!confirm(`Remove passkey “${item.name}”?`)) return;
      remove.disabled = true;
      let proof;
      try {
        if (!$('#passkeyPassword').value) throw new Error('Enter your master password to remove a passkey.');
        proof = await C.deriveKeys(argon, $('#passkeyPassword').value, S.salt, S.kdf);
        const body = { auth_key: C.b64e(proof.authKey),
          ...await secondFactorFields(proof.authKey, $('#passkeyFactor').value.trim()) };
        await api('DELETE', `/auth/passkeys/${encodeURIComponent(item.id)}`, body);
        $('#passkeyPassword').value = $('#passkeyFactor').value = '';
        await renderPasskeys();
      } catch (e) { $('#passkeyStatus').textContent = e.detail === 'otp_required' ?
        'Enter your authenticator/recovery code or confirm with an existing passkey.' : e.message; }
      finally { proof?.encKey.fill(0); proof?.authKey.fill(0); remove.disabled = false; }
    });
    row.append(name, remove); list.append(row);
  }
}
$('#btnPasskeys').onclick = async () => {
  $('#passkeyStatus').textContent = ''; $('#dlgPasskeys').showModal();
  try { await renderPasskeys(); } catch (e) { $('#passkeyStatus').textContent = e.message; }
};
$('#addPasskey').onclick = async () => {
  const button = $('#addPasskey'), status = $('#passkeyStatus'); button.disabled = true; status.textContent = '';
  let proof;
  try {
    if (!navigator.credentials?.create || !navigator.credentials?.get) throw new Error('This browser does not support WebAuthn passkeys.');
    proof = await C.deriveKeys(argon, $('#passkeyPassword').value, S.salt, S.kdf);
    const ceremonyBody = { auth_key: C.b64e(proof.authKey),
      ...await secondFactorFields(proof.authKey, $('#passkeyFactor').value.trim()) };
    const ceremony = await api('POST', '/auth/passkeys/registration-options', ceremonyBody);
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(ceremony.options) });
    if (!credential) throw new Error('Passkey creation was cancelled.');
    await api('POST', '/auth/passkeys/register', { challenge_id: ceremony.challenge_id,
      credential: webauthnJSON(credential), name: $('#passkeyName').value.trim() || 'Passkey' });
    $('#passkeyPassword').value = $('#passkeyFactor').value = '';
    status.textContent = 'Passkey added. It can now be used instead of a TOTP code after the master password.';
    await renderPasskeys();
  } catch (e) { status.textContent = e.detail === 'otp_required' ? 'Enter your authenticator or recovery code, then try again.' : (e.message || 'Could not register a passkey.'); }
  finally { proof?.encKey.fill(0); proof?.authKey.fill(0); button.disabled = false; $('#passkeyPassword').value = $('#passkeyFactor').value = ''; }
};
$('#closePasskeys').onclick = () => $('#dlgPasskeys').close();

// ---- user-held recovery key ----
$('#btnRecovery').onclick = () => {
  $('#setupRecoveryPassword').value = ''; $('#newRecoveryKey').textContent = '';
  $('#newRecoveryKey').hidden = $('#copyRecoveryKey').hidden = true;
  $('#recoverySetupStatus').textContent = ''; $('#dlgRecoverySetup').showModal();
};
$('#createRecovery').onclick = async () => {
  const button = $('#createRecovery'), status = $('#recoverySetupStatus'); button.disabled = true; status.textContent = '';
  let secret, keys, proof;
  try {
    proof = await C.deriveKeys(argon, $('#setupRecoveryPassword').value, S.salt, S.kdf);
    secret = C.rand(32); const salt = C.rand(16); keys = await C.deriveRecoveryKeys(secret, salt);
    const payload = { auth_key: C.b64e(proof.authKey), recovery_auth_key: C.b64e(keys.authKey),
      recovery_salt: C.b64e(salt), recovery_wrapped_key: C.b64e(await C.encrypt(keys.encKey, S.vaultKey, C.RECOVERY_KEY_AAD)),
      recovery_wrapped_private_key: C.b64e(await C.encrypt(keys.encKey, S.priv, C.RECOVERY_PRIVATE_AAD)),
      ...await secondFactorFields(proof.authKey, $('#setupRecoveryFactor').value.trim()) };
    await api('POST', '/auth/recovery/setup', payload);
    $('#newRecoveryKey').textContent = C.b64e(secret);
    $('#newRecoveryKey').hidden = $('#copyRecoveryKey').hidden = false;
    status.textContent = 'Recovery key created. Copy it now and store it offline; closing this window clears it.';
  } catch (e) { status.textContent = e.detail === 'otp_required' ? 'Enter your authenticator or recovery code, then try again.' : e.message; }
  finally { secret?.fill(0); keys?.encKey.fill(0); keys?.authKey.fill(0); proof?.encKey.fill(0); proof?.authKey.fill(0); button.disabled = false; $('#setupRecoveryPassword').value = $('#setupRecoveryFactor').value = ''; }
};
$('#copyRecoveryKey').onclick = () => copy($('#newRecoveryKey').textContent, 'Recovery key');
$('#closeRecoverySetup').onclick = () => {
  $('#newRecoveryKey').textContent = ''; $('#newRecoveryKey').hidden = $('#copyRecoveryKey').hidden = true;
  $('#dlgRecoverySetup').close();
};
$('#dlgRecoverySetup').addEventListener('close', () => {
  $('#newRecoveryKey').textContent = ''; $('#newRecoveryKey').hidden = $('#copyRecoveryKey').hidden = true;
  $('#setupRecoveryPassword').value = $('#setupRecoveryFactor').value = '';
});
$('#recoverAccount').onclick = () => {
  $('#recoveryEmail').value = $('#email').value.trim();
  $('#recoveryKey').value = $('#recoveryNew').value = $('#recoveryConfirm').value = $('#recoveryFactor').value = '';
  $('#recoveryStatus').textContent = ''; $('#dlgRecovery').showModal();
};
$('#completeRecovery').onclick = async () => {
  const button = $('#completeRecovery'), status = $('#recoveryStatus'); button.disabled = true; status.textContent = '';
  let recoveryBytes, recoveryKeys, vaultKey, privateKey, newMaterial;
  try {
    const email = $('#recoveryEmail').value.trim().toLowerCase();
    const recoveryValue = $('#recoveryKey').value.trim();
    const nextPassword = $('#recoveryNew').value;
    if (nextPassword.length < 12) throw new Error('New master password must be at least 12 characters.');
    if (nextPassword !== $('#recoveryConfirm').value) throw new Error('New master passwords do not match.');
    recoveryBytes = C.b64d(recoveryValue);
    const options = await api('POST', '/auth/recovery/options', { email });
    recoveryKeys = await C.deriveRecoveryKeys(recoveryBytes, C.b64d(options.recovery_salt));
    vaultKey = await C.decrypt(recoveryKeys.encKey, C.b64d(options.recovery_wrapped_key), C.RECOVERY_KEY_AAD);
    if (options.recovery_wrapped_private_key) {
      try { privateKey = await C.decrypt(recoveryKeys.encKey, C.b64d(options.recovery_wrapped_private_key), C.RECOVERY_PRIVATE_AAD); }
      catch { /* A fixed-size placeholder is returned when no recovery copy exists. */ }
    }
    const newSalt = C.rand(16); newMaterial = await C.deriveKeys(argon, nextPassword, newSalt, KDF);
    const body = { email, recovery_auth_key: C.b64e(recoveryKeys.authKey), new_auth_key: C.b64e(newMaterial.authKey),
      new_salt: C.b64e(newSalt), new_kdf: KDF, new_wrapped_key: C.b64e(await C.encrypt(newMaterial.encKey, vaultKey, C.WRAP_AAD)),
      new_wrapped_private_key: privateKey ? C.b64e(await C.encrypt(newMaterial.encKey, privateKey, C.PRIV_AAD)) : undefined };
    const factor = $('#recoveryFactor').value.trim();
    if (factor) body[/^\d{6}$/.test(factor) ? 'otp' : 'recovery_code'] = factor;
    const login = await api('POST', '/auth/recovery/complete', body);
    $('#dlgRecovery').close(); $('#recoveryKey').value = $('#recoveryNew').value = $('#recoveryConfirm').value = $('#recoveryFactor').value = '';
    await completeLogin(login, { email, salt: newSalt, kdf: KDF, encKey: newMaterial.encKey });
  } catch (e) {
    status.textContent = e.detail === 'otp_required' ? 'Enter your authenticator or recovery code, then try again.' :
      'Recovery failed. Check the email, recovery key, new password, and any required second factor.';
  } finally {
    recoveryBytes?.fill(0); recoveryKeys?.encKey.fill(0); recoveryKeys?.authKey.fill(0);
    vaultKey?.fill(0); privateKey?.fill(0); newMaterial?.authKey.fill(0); button.disabled = false;
  }
};
$('#closeRecovery').onclick = () => {
  ['#recoveryKey', '#recoveryNew', '#recoveryConfirm', '#recoveryFactor'].forEach((s) => { $(s).value = ''; });
  $('#dlgRecovery').close();
};
$('#dlgRecovery').addEventListener('close', () => {
  ['#recoveryKey', '#recoveryNew', '#recoveryConfirm', '#recoveryFactor'].forEach((s) => { $(s).value = ''; });
});

// ---- vault ----
async function load() {
  const rows = await api('GET', ctx ? `/vaults/${ctx.id}/entries` : '/entries');
  const open = ctx ? (r) => C.openShared(ctx.key, ctx.id, r) : (r) => C.open(S.vaultKey, r);
  $('#add').hidden = $('#emptyAdd').hidden = ctx?.role === 'viewer';
  entries = (await Promise.all(rows.map((r) => open(r).catch(() => null)))).filter(Boolean)
    .sort((a, b) => a.site.toLowerCase().localeCompare(b.site.toLowerCase()));
  if (entries.length < rows.length) toast('Some entries could not be decrypted (corrupted or tampered).');
  render();
}
function btn(label, fn) { const b = document.createElement('button'); b.textContent = label; b.className = 'ghost'; b.onclick = fn; return b; }
function render() {
  const q = $('#search').value.toLowerCase(), list = $('#list');
  const shown = entries.filter((e) => e.site.toLowerCase().includes(q) || e.username.toLowerCase().includes(q));
  $('#empty').hidden = entries.length > 0;
  list.replaceChildren(...shown.map((e) => {         // textContent only: entry data is never parsed as HTML
    const li = document.createElement('li'), t = document.createElement('b'), u = document.createElement('span'), p = document.createElement('span');
    t.textContent = e.site; u.textContent = e.username || '—'; u.className = 'hint'; p.className = 'pw'; p.textContent = '••••••••••';
    p.hidden = !e.password;
    const kind = document.createElement('span'); kind.className = 'tag';
    kind.textContent = ({ login: 'Login', secure_note: 'Secure note', card: 'Payment card', identity: 'Identity', passkey: 'Passkey' })[e.type || 'login'] || 'Login';
    let shownPw = false;
    const row = document.createElement('div'); row.className = 'row';
    row.append(
      ...(e.password ? [btn('Copy password', () => copy(e.password, 'Password'))] : []),
      ...(e.username ? [btn('Copy username', () => copy(e.username, 'Username'))] : []),
      ...(e.password ? [btn('Show', (ev) => { shownPw = !shownPw; p.textContent = shownPw ? e.password : '••••••••••'; ev.target.textContent = shownPw ? 'Hide' : 'Show'; })] : []),
      ...(!ctx ? [btn('History', () => showHistory(e))] : []),
      ...(ctx?.role === 'viewer' ? [] : [btn('Edit', () => openEntry(e)),
        btn('Delete', async () => {
          if (!confirm(`Delete "${e.site}"?`)) return;
          try { await api('DELETE', epath() + e.id); }
          catch (err) { toast(err.message); return; }
          try { await load(); } catch (err) { toast('Deleted, but the vault could not refresh: ' + err.message); }
        })]));
    li.append(t, kind, u, p, row); return li;
  }));
}
async function showHistory(entry) {
  const body = $('#historyBody'); body.replaceChildren(); $('#dlgHistory').showModal();
  try {
    const rows = await api('GET', `/entries/${entry.id}/history`);
    if (!rows.length) { body.textContent = 'No previous versions yet. Edits will be saved here.'; return; }
    for (const r of rows) {
      const line = document.createElement('div'); line.className = 'row';
      const text = document.createElement('span'); text.textContent = `Version ${r.version} · ${new Date(r.created_at).toLocaleString()}`;
      const restore = btn('Restore', async () => {
        if (!confirm(`Restore version ${r.version}? The current version will remain in history.`)) return;
        restore.disabled = true;
        try {
          await C.open(S.vaultKey, { id: entry.id, blob: r.blob, version: r.version });
          await api('PUT', `/entries/${entry.id}`, { blob: r.blob, version: entry.version });
          $('#dlgHistory').close(); await load(); toast(`Restored version ${r.version}.`);
        } catch (e) { toast(e.message); restore.disabled = false; }
      });
      line.append(text, restore); body.append(line);
    }
  } catch (e) { body.textContent = e.message; }
}
$('#closeHistory').onclick = () => $('#dlgHistory').close();
$('#search').oninput = render;

function openEntry(e) {
  if (e?.type === 'passkey') { toast('This stored passkey record is not usable by PWVault.'); return; }
  editing = e; $('#entryTitle').textContent = e ? 'Edit entry' : 'Add entry'; $('#entryErr').textContent = '';
  $('#fType').value = e?.type || 'login';
  $('#fSite').value = e?.site || ''; $('#fUser').value = e?.username || ''; $('#fPass').value = e?.password || ''; $('#fNotes').value = e?.notes || '';
  activeAttachments = (e?.attachments || []).map((a) => ({ ...a }));
  customRows = Object.entries(e?.fields || {}).map(([name, value]) => ({ name, value }));
  renderCustomFields(); renderAttachments(); updateEntryType();
  meter($('#meter2'), $('#fPass').value); $('#breachRes').textContent = ''; setPwVisible(false); $('#dlgEntry').showModal();
}
function updateEntryType() {
  const login = $('#fType').value === 'login';
  $('#fUserRow').hidden = $('#fPassRow').hidden = $('#meter2').hidden = $('#loginOnly').hidden = !login;
  $('#fPass').required = login;
}
$('#fType').onchange = updateEntryType;
function renderCustomFields() {
  const root = $('#customFields'); root.replaceChildren();
  customRows.forEach((f, index) => {
    const row = document.createElement('div'); row.className = 'row';
    const name = Object.assign(document.createElement('input'), { value: f.name, placeholder: 'Field name', maxLength: 80, 'aria-label': 'Field name' });
    const value = Object.assign(document.createElement('input'), { value: f.value, placeholder: 'Value', maxLength: 4096, 'aria-label': 'Field value' });
    name.oninput = () => { f.name = name.value; }; value.oninput = () => { f.value = value.value; };
    const remove = btn('Remove', () => { customRows.splice(index, 1); renderCustomFields(); });
    row.append(name, value, remove); root.append(row);
  });
}
$('#addCustomField').onclick = () => {
  if (customRows.length >= 32) { toast('A record can have at most 32 custom fields.'); return; }
  customRows.push({ name: '', value: '' }); renderCustomFields();
};
function renderAttachments() {
  const root = $('#attachmentList'); root.replaceChildren();
  activeAttachments.forEach((file, index) => {
    const row = document.createElement('div'); row.className = 'row';
    const name = document.createElement('span'); name.textContent = `${file.name} (${Math.ceil(file.size / 1024)} KB)`;
    const download = btn('Download', () => {
      try {
        const blob = new Blob([C.b64d(file.data)], { type: file.type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob), a = Object.assign(document.createElement('a'), { href: url, download: file.name });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
      } catch { toast('This attachment could not be opened.'); }
    });
    const remove = btn('Remove', () => { activeAttachments.splice(index, 1); renderAttachments(); });
    row.append(name, download, remove); root.append(row);
  });
}
$('#fFiles').onchange = async () => {
  const files = [...$('#fFiles').files], total = activeAttachments.reduce((n, f) => n + f.size, 0) + files.reduce((n, f) => n + f.size, 0);
  if (activeAttachments.length + files.length > 5 || total > 2 * 1024 * 1024) {
    toast('Attachments are limited to 5 files and 2 MB total.'); $('#fFiles').value = ''; return;
  }
  try {
    for (const file of files) activeAttachments.push({ name: file.name.slice(0, 255), type: file.type.slice(0, 128),
      size: file.size, data: C.b64e(new Uint8Array(await file.arrayBuffer())) });
    renderAttachments();
  } catch { toast('Could not read the selected attachment.'); }
  $('#fFiles').value = '';
};
$('#add').onclick = () => openEntry(null);
$('#cancel').onclick = () => $('#dlgEntry').close();
function clearEntryDialog() {
  $('#fSite').value = $('#fUser').value = $('#fPass').value = $('#fNotes').value = '';
  $('#fFiles').value = ''; activeAttachments = []; customRows = []; editing = null;
  $('#customFields').replaceChildren(); $('#attachmentList').replaceChildren();
  $('#meter2').dataset.score = '0'; $('#meter2').querySelector('small').textContent = '';
}
$('#dlgEntry').addEventListener('close', clearEntryDialog);
$('#gen').onclick = () => { $('#fPass').value = C.generatePassword(20); setPwVisible(true); meter($('#meter2'), $('#fPass').value); };
$('#fPass').oninput = () => meter($('#meter2'), $('#fPass').value);
$('#entryForm').onsubmit = async (ev) => {
  ev.preventDefault(); const save = $('#entryForm button.primary');
  if (save.disabled) return;
  save.disabled = true;
  const fields = {};
  for (const f of customRows) {
    const name = f.name.trim();
    if (!name) continue;
    if (Object.hasOwn(fields, name)) { $('#entryErr').textContent = 'Custom field names must be unique.'; save.disabled = false; return; }
    fields[name] = f.value;
  }
  const e = { type: $('#fType').value, site: $('#fSite').value.trim(), username: $('#fUser').value,
    password: $('#fPass').value, notes: $('#fNotes').value, fields, attachments: activeAttachments.slice() };
  try {
    const seal = (id) => (ctx ? C.sealShared(ctx.key, ctx.id, id, ctx.kv, e) : C.seal(S.vaultKey, id, e));
    const extra = ctx ? { key_version: ctx.kv } : {};
    if (editing) await api('PUT', epath() + editing.id, { blob: await seal(editing.id), version: editing.version, ...extra });
    else { const id = crypto.randomUUID(); await api('POST', ctx ? `/vaults/${ctx.id}/entries` : '/entries', { id, blob: await seal(id), ...extra }); }
    $('#dlgEntry').close();
    try { await load(); } catch (x) { toast('Saved, but the vault could not refresh: ' + x.message); }
  } catch (x) { $('#entryErr').textContent = x.status === 409 ? 'Changed elsewhere, reload and retry.' : x.message; }
  finally { save.disabled = false; }
};

// ---- encrypted backups and local CSV import ----
const BACKUP_AAD = 'pwvault:encrypted-backup:v1';
const BACKUP_KDF = { time_cost: 3, memory_cost_kib: 65536, parallelism: 4 };
const encoder = new TextEncoder(), decoder = new TextDecoder();
let pendingFormat = '';
function parseCsv(text) {
  const rows = []; let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"' && cell === '') quoted = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); if (row.some((v) => v.trim())) rows.push(row); row = []; cell = '';
    } else cell += ch;
  }
  if (quoted) throw new Error('CSV has an unclosed quoted field.');
  row.push(cell); if (row.some((v) => v.trim())) rows.push(row);
  if (rows.length < 2) throw new Error('CSV contains no entries.');
  const headers = rows.shift().map((v) => v.replace(/^\uFEFF/, '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '_'));
  const col = (...names) => names.map((n) => headers.indexOf(n)).find((i) => i >= 0);
  const siteCol = col('login_uri', 'url', 'website', 'origin', 'domain', 'name', 'title');
  const nameCol = col('name', 'title');
  const userCol = col('login_username', 'username', 'user', 'email');
  const passCol = col('login_password', 'password', 'pass');
  const noteCol = col('notes', 'extra', 'note');
  if (siteCol === undefined || passCol === undefined) throw new Error('CSV needs a website/name column and a password column.');
  return rows.map((r) => ({ type: 'login', site: (r[siteCol] || (nameCol === undefined ? '' : r[nameCol]) || '').trim(),
    username: userCol === undefined ? '' : r[userCol] || '', password: r[passCol] || '',
    notes: noteCol === undefined ? '' : r[noteCol] || '', fields: {}, attachments: [] }))
    .filter((e) => e.site && e.password).slice(0, 5000);
}
function validateImport(rows) {
  if (!Array.isArray(rows) || rows.length > 5000) throw new Error('Backup has an unsupported number of entries.');
  return rows.map((e) => {
    if (!e || typeof e.site !== 'string' || typeof e.username !== 'string' ||
        typeof e.password !== 'string' || typeof e.notes !== 'string' ||
        e.site.length > 1024 || e.username.length > 2048 || e.password.length > 4096 || e.notes.length > 20000)
      throw new Error('Backup contains an invalid or oversized entry.');
    const type = e.type || 'login';
    if (!['login', 'secure_note', 'card', 'identity', 'passkey'].includes(type)) throw new Error('Backup contains an unsupported item type.');
    const fields = e.fields || {}, attachments = e.attachments || [];
    if (!fields || typeof fields !== 'object' || Array.isArray(fields) || Object.keys(fields).length > 32 ||
        Object.entries(fields).some(([k, v]) => typeof k !== 'string' || k.length > 80 || typeof v !== 'string' || v.length > 4096))
      throw new Error('Backup contains invalid custom fields.');
    if (!Array.isArray(attachments) || attachments.length > 5 || attachments.reduce((n, a) => n + (a?.size || 0), 0) > 2 * 1024 * 1024 ||
        attachments.some((a) => !a || typeof a.name !== 'string' || typeof a.type !== 'string' || !Number.isInteger(a.size) || a.size < 0 ||
          typeof a.data !== 'string' || a.data.length > 2_800_000 || C.b64d(a.data).length !== a.size))
      throw new Error('Backup contains invalid or oversized attachments.');
    return { type, site: e.site, username: e.username, password: e.password, notes: e.notes, fields, attachments };
  }).filter((e) => e.site && (e.type !== 'login' || e.password));
}
function importDedupeKey(e) {
  const base = `${(e.type || 'login')}\0${e.site.trim().toLowerCase()}\0${e.username.trim().toLowerCase()}`;
  // Preserve distinct notes/cards/identities that share a label. Login entries
  // keep the familiar site+username duplicate rule when importing a backup.
  return e.type === 'login' || !e.type ? `login\0${e.site.trim().toLowerCase()}\0${e.username.trim().toLowerCase()}`
    : `${base}\0${JSON.stringify({ notes: e.notes, fields: e.fields, attachments: e.attachments })}`;
}
function setImportPreview(rows, format) {
  const existing = new Set(entries.map(importDedupeKey));
  const unique = new Set();
  pendingImport = validateImport(rows).filter((e) => {
    const key = importDedupeKey(e);
    if (existing.has(key) || unique.has(key)) return false;
    unique.add(key); return true;
  });
  pendingFormat = format;
  $('#applyImport').hidden = pendingImport.length === 0;
  $('#backupStatus').textContent = `${pendingImport.length} new ${format} entr${pendingImport.length === 1 ? 'y' : 'ies'} ready. Matching site and username pairs already in the vault will be skipped.`;
}
$('#btnBackup').onclick = () => {
  if (ctx) { toast('Switch to your personal vault to import or export.'); return; }
  pendingImport = []; $('#applyImport').hidden = true;
  $('#backupPass').value = $('#backupConfirm').value = $('#importPass').value = '';
  $('#importFile').value = ''; $('#backupStatus').textContent = ''; $('#dlgBackup').showModal();
};
$('#exportBackup').onclick = async () => {
  const pass = $('#backupPass').value;
  if (pass.length < 12) { $('#backupStatus').textContent = 'Use a separate backup passphrase of at least 12 characters.'; return; }
  if (pass !== $('#backupConfirm').value) { $('#backupStatus').textContent = 'The backup passphrases do not match.'; return; }
  const btn = $('#exportBackup'); btn.disabled = true; let key, payload;
  try {
    const salt = C.rand(16);
    key = await argon({ password: pass, salt, parallelism: BACKUP_KDF.parallelism,
      iterations: BACKUP_KDF.time_cost, memorySize: BACKUP_KDF.memory_cost_kib, hashLength: 32, outputType: 'binary' });
    payload = encoder.encode(JSON.stringify({ entries: entries.map(({ type, site, username, password, notes, fields, attachments }) =>
      ({ type: type || 'login', site, username, password, notes, fields: fields || {}, attachments: attachments || [] })) }));
    if (payload.length > 9 * 1024 * 1024) throw new Error('This vault is too large for one backup file.');
    const blob = await C.encrypt(key, payload, BACKUP_AAD);
    const backup = { format: 'pwvault-encrypted-backup', version: 1, kdf: BACKUP_KDF,
      salt: C.b64e(salt), blob: C.b64e(blob) };
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: 'pwvault-encrypted-backup.json' });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000);
    $('#backupStatus').textContent = 'Encrypted backup downloaded. Keep the passphrase separate from the file.';
  } catch (e) { $('#backupStatus').textContent = e.message; }
  finally { key?.fill(0); payload?.fill(0); btn.disabled = false; $('#backupPass').value = $('#backupConfirm').value = ''; }
};
$('#previewImport').onclick = async () => {
  const file = $('#importFile').files[0]; pendingImport = []; $('#applyImport').hidden = true;
  if (!file) { $('#backupStatus').textContent = 'Choose a backup or CSV file first.'; return; }
  if (file.size > 10 * 1024 * 1024) { $('#backupStatus').textContent = 'Files must be smaller than 10 MB.'; return; }
  const btn = $('#previewImport'); btn.disabled = true;
  try {
    const raw = await file.text();
    if (file.name.toLowerCase().endsWith('.csv')) setImportPreview(parseCsv(raw), 'CSV');
    else {
      const backup = JSON.parse(raw);
      if (backup.format !== 'pwvault-encrypted-backup' || backup.version !== 1 ||
          !backup.kdf || !Number.isInteger(backup.kdf.time_cost) || backup.kdf.time_cost < 1 || backup.kdf.time_cost > 6 ||
          !Number.isInteger(backup.kdf.memory_cost_kib) || backup.kdf.memory_cost_kib < 8 || backup.kdf.memory_cost_kib > 131072 ||
          !Number.isInteger(backup.kdf.parallelism) || backup.kdf.parallelism < 1 || backup.kdf.parallelism > 4 ||
          backup.kdf.memory_cost_kib < 8 * backup.kdf.parallelism) throw new Error('Unsupported backup format or KDF settings.');
      const pass = $('#importPass').value; if (!pass) throw new Error('Enter the backup passphrase.');
      const key = await argon({ password: pass, salt: C.b64d(backup.salt), parallelism: backup.kdf.parallelism,
        iterations: backup.kdf.time_cost, memorySize: backup.kdf.memory_cost_kib, hashLength: 32, outputType: 'binary' });
      let plaintext;
      try {
        plaintext = await C.decrypt(key, C.b64d(backup.blob), BACKUP_AAD);
        const payload = JSON.parse(decoder.decode(plaintext));
        setImportPreview(payload.entries, 'backup');
      } finally { key.fill(0); plaintext?.fill(0); $('#importPass').value = ''; }
    }
  } catch { $('#backupStatus').textContent = 'Could not read this file. Check that it is a supported CSV or that the backup passphrase is correct.'; }
  finally { btn.disabled = false; }
};
$('#applyImport').onclick = async () => {
  const btn = $('#applyImport'); btn.disabled = true;
  let added = 0;
  try {
    while (pendingImport.length) {
      const e = pendingImport[0], id = crypto.randomUUID();
      await api('POST', '/entries', { id, blob: await C.seal(S.vaultKey, id, e) });
      entries.push({ ...e, id, version: 1 }); pendingImport.shift(); added++;
    }
    await load(); $('#backupStatus').textContent = `${added} entries imported from ${pendingFormat}.`;
    btn.hidden = true;
  } catch (e) { $('#backupStatus').textContent = `${added} imported; ${pendingImport.length} remain. ${e.message}`; }
  finally { btn.disabled = false; }
};
$('#closeBackup').onclick = () => { pendingImport = []; $('#dlgBackup').close(); };
$('#dlgBackup').addEventListener('close', () => {
  pendingImport = []; $('#backupPass').value = $('#backupConfirm').value = $('#importPass').value = '';
  $('#importFile').value = ''; $('#backupStatus').textContent = ''; $('#applyImport').hidden = true;
});

// ---- 2FA enrolment ----
$('#btn2fa').onclick = async () => {
  const body = $('#twofaBody'); body.replaceChildren(); $('#dlg2fa').showModal();
  const p = (t) => Object.assign(document.createElement('p'), { textContent: t });
  try {
    if ((await api('GET', '/auth/me')).totp_enabled) { body.append(p('Two-factor authentication is enabled.')); return; }
    const prompt = document.createElement('label'); prompt.textContent = 'Confirm master password';
    const password = Object.assign(document.createElement('input'), { type: 'password', autocomplete: 'current-password' });
    const verify = Object.assign(document.createElement('button'), { textContent: 'Continue', className: 'primary' });
    const err = Object.assign(document.createElement('p'), { className: 'err' });
    prompt.append(password);
    verify.onclick = async () => {
      verify.disabled = true; err.textContent = '';
      let proof;
      try {
        proof = await C.deriveKeys(argon, password.value, S.salt, S.kdf);
        const body = { auth_key: C.b64e(proof.authKey), ...await secondFactorFields(proof.authKey) };
        const { secret, otpauth_uri } = await api('POST', '/auth/2fa/setup', body);
        password.value = '';
        const qr = qrcode(0, 'M'); qr.addData(otpauth_uri); qr.make();
        const img = Object.assign(document.createElement('img'), { src: qr.createDataURL(5), alt: 'QR code', className: 'qr' });
        const code = Object.assign(document.createElement('input'), { placeholder: '6-digit code', inputMode: 'numeric', maxLength: 6 });
        const ok = Object.assign(document.createElement('button'), { textContent: 'Verify and enable', className: 'primary' });
        const setupErr = Object.assign(document.createElement('p'), { className: 'err' });
        ok.onclick = async () => { try {
          const { recovery_codes } = await api('POST', '/auth/2fa/enable', { code: code.value.trim() });
          const pre = Object.assign(document.createElement('code'), { textContent: recovery_codes.join('\n'), style: 'white-space:pre' });
          body.replaceChildren(p('Enabled. Save these recovery codes now; they are shown only once:'), pre);
        } catch { setupErr.textContent = 'Invalid code, try again.'; } };
        body.replaceChildren(p('Scan with an authenticator app, or enter the key manually:'), img,
          Object.assign(document.createElement('code'), { textContent: secret }), code, ok, setupErr);
      } catch (e) {
        err.textContent = e.message;
        verify.disabled = false;
      } finally {
        proof?.encKey.fill(0); proof?.authKey.fill(0); password.value = '';
      }
    };
    body.append(prompt, verify, err);
  } catch (e) { body.append(p(e.message)); }
};
$('#close2fa').onclick = () => { $('#dlg2fa').close(); $('#twofaBody').replaceChildren(); };

// ---- breach check: only a 5-char hash prefix leaves this page, relayed by our server ----
async function breaches(pw) {
  const { prefix, suffix } = await C.sha1Split(pw);
  const r = await fetch('/breach/range/' + prefix, { headers: { Authorization: 'Bearer ' + S.token } });
  if (!r.ok) throw new Error(r.status === 503 ? 'Breach check is disabled on this server.' : 'Breach service unavailable.');
  return C.countInRange(await r.text(), suffix);
}
$('#chk').onclick = async () => {
  const out = $('#breachRes'); out.textContent = 'Checking…';
  try { const n = await breaches($('#fPass').value);
    out.textContent = n ? `⚠ Found in ${n.toLocaleString()} known breaches. Choose another.` : '✅ Not found in known breaches.';
  } catch (e) { out.textContent = e.message; }
};

// ---- vault health: weak / reused (local) + breached (k-anonymity) ----
const para = (parent, text, cls) => { const p = document.createElement('p'); p.textContent = text; if (cls) p.className = cls; parent.append(p); return p; };
$('#btnHealth').onclick = async () => {
  const body = $('#healthBody'); body.replaceChildren(); $('#dlgHealth').showModal();
  const weak = entries.filter((e) => C.strength(e.password).score <= 1), by = {};
  entries.forEach((e) => (by[e.password] ??= []).push(e.site));
  const reused = Object.values(by).filter((v) => v.length > 1);
  para(body, `${entries.length} entries checked.`, 'hint');
  para(body, weak.length ? '⚠ Weak: ' + weak.map((e) => e.site).join(', ') : '✅ No weak passwords.');
  para(body, reused.length ? '⚠ Reused: ' + reused.map((v) => v.join(' + ')).join('; ') : '✅ No reused passwords.');
  const line = para(body, 'Checking known breaches…', 'hint');
  try {
    const bad = []; for (const pw of Object.keys(by)) if (await breaches(pw)) bad.push(...by[pw]);
    line.className = ''; line.textContent = bad.length ? '❌ In known breaches: ' + bad.join(', ') : '✅ None found in known breaches.';
  } catch (e) { line.textContent = e.message; }
};
$('#closeHealth').onclick = () => $('#dlgHealth').close();

// ---- admin console (server enforces admin-only; this is just the screen) ----
let adminTab = 'users';
async function adminRender() {
  const body = $('#adminBody'); body.replaceChildren();
  $('#tabUsers').classList.toggle('on', adminTab === 'users'); $('#tabAudit').classList.toggle('on', adminTab === 'audit');
  try {
    if (adminTab === 'users') {
      const inv = document.createElement('div'); inv.className = 'row';
      const em = Object.assign(document.createElement('input'), { type: 'email', placeholder: 'colleague@example.dz' });
      const go = Object.assign(document.createElement('button'), { textContent: 'Invite', className: 'primary' }), res = document.createElement('p');
      go.onclick = async () => { try { const r = await api('POST', '/admin/invites', { email: em.value.trim() });
        res.className = 'mono'; res.textContent = `Code for ${r.email} (single use, valid 7 days, send it privately): ${r.code}`; em.value = ''; } catch (e) { res.className = 'err'; res.textContent = e.message; } };
      inv.append(em, go); body.append(inv, res);
      const ul = document.createElement('ul');
      for (const u of await api('GET', '/admin/users')) {
        const li = document.createElement('li'), row = document.createElement('div'); row.className = 'row';
        const tags = [u.role, u.totp_enabled ? '2FA on' : '2FA off', `${u.entry_count} entries`, u.disabled && 'disabled', u.locked && 'locked'].filter(Boolean);
        const name = document.createElement('b'); name.textContent = u.email; li.append(name);
        tags.forEach((t) => { const s = document.createElement('span'); s.className = 'tag'; s.textContent = t; row.append(s); });
        if (u.id !== S.id) {
          const act = (label, fn) => row.append(btn(label, async () => { try { await fn(); } catch (e) { toast(e.message); } adminRender(); }));
          act(u.role === 'admin' ? 'Make employee' : 'Make admin', () => api('PUT', `/admin/users/${u.id}/role`, { role: u.role === 'admin' ? 'employee' : 'admin' }));
          act(u.disabled ? 'Enable' : 'Disable', () => api('POST', `/admin/users/${u.id}/${u.disabled ? 'enable' : 'disable'}`));
          if (u.locked) act('Unlock', () => api('POST', `/admin/users/${u.id}/unlock`));
        }
        li.append(row); ul.append(li);
      }
      body.append(ul);
    } else {
      const v = await api('GET', '/admin/audit/verify');
      para(body, v.valid ? `✅ Audit chain intact: ${v.checked} records. Head ${(v.head_hash || '').slice(0, 16)}…`
                         : `❌ TAMPERING DETECTED at record ${v.first_bad_seq}: ${v.reason}`, v.valid ? 'ok' : 'err');
      for (const r of await api('GET', '/admin/audit?limit=50')) para(body, `${r.seq} ${r.ts} ${r.action} ${r.detail}`, 'mono');
    }
  } catch (e) { para(body, e.message, 'err'); }
}
$('#btnAdmin').onclick = () => { adminTab = 'users'; $('#dlgAdmin').showModal(); adminRender(); };
$('#tabUsers').onclick = () => { adminTab = 'users'; adminRender(); };
$('#tabAudit').onclick = () => { adminTab = 'audit'; adminRender(); };
$('#closeAdmin').onclick = () => $('#dlgAdmin').close();

// ---- keypair: load (or create once) the X25519 identity used for sharing ----
async function initKeys(d, encKey) {
  if (d.wrapped_private_key) {
    S.priv = await C.decrypt(encKey, C.b64d(d.wrapped_private_key), C.PRIV_AAD);
    S.pub = await C.publicFromPrivate(S.priv);
    if (C.b64e(S.pub) !== d.public_key) throw new Error('The server returned a public key that is not yours. Aborting.');
  } else {
    const kp = await C.generateKeypair(); S.priv = kp.priv; S.pub = kp.pub;
    await api('PUT', '/auth/keypair', { public_key: C.b64e(kp.pub), wrapped_private_key: C.b64e(await C.encrypt(encKey, kp.priv, C.PRIV_AAD)) });
  }
}

// ---- shared vaults ----
const epath = () => (ctx ? `/vaults/${ctx.id}/entries/` : '/entries/');
async function loadVaults(selectId = '') {
  vaults = [];
  for (const r of await api('GET', '/vaults')) {
    try {
      const key = await C.unwrap(S.priv, C.b64d(r.wrapped_key), C.keyAad(r.id, S.id, r.key_version));
      vaults.push({ id: r.id, role: r.role, kv: r.key_version, key, name: await C.decText(key, C.b64d(r.name_blob), C.nameAad(r.id, r.key_version)) });
    } catch { toast('A shared vault could not be opened (keys do not match).'); }
  }
  const sel = $('#vaultSel');
  sel.replaceChildren(new Option('Personal vault', ''), ...vaults.map((v) => new Option(`${v.name} (${v.role})`, v.id)));
  sel.value = vaults.some((v) => v.id === selectId) ? selectId : '';
  ctx = vaults.find((v) => v.id === sel.value) || null;
  $('#btnMembers').hidden = !ctx;
}
$('#vaultSel').onchange = async (ev) => {
  ctx = vaults.find((v) => v.id === ev.target.value) || null; $('#btnMembers').hidden = !ctx; $('#search').value = '';
  entries = []; render();
  try { await load(); } catch (e) { toast(e.message); }
};
$('#newVault').onclick = async () => {
  const name = prompt('Name of the new shared vault:'); if (!name || !name.trim()) return;
  try {
    const id = crypto.randomUUID(), key = C.rand(32);
    await api('POST', '/vaults', { id, name_blob: C.b64e(await C.encText(key, name.trim(), C.nameAad(id, 1))),
      wrapped_key: C.b64e(await C.wrapFor(S.pub, key, C.keyAad(id, S.id, 1))) });
    await loadVaults(id); await load();
  } catch (e) { toast(e.message); }
};

async function renderMembers() {
  const body = $('#membersBody'), owner = ctx.role === 'owner'; body.replaceChildren();
  $('#membersTitle').textContent = `${ctx.name}: members`;
  $('#addMember').hidden = $('#delVault').hidden = !owner;
  para(body, 'Your key fingerprint: ' + await C.fingerprint(S.pub), 'mono');
  const ul = document.createElement('ul');
  for (const m of await api('GET', `/vaults/${ctx.id}/members`)) {
    const li = document.createElement('li'), row = document.createElement('div'); row.className = 'row';
    const name = document.createElement('b'); name.textContent = `${m.email} · ${m.role}`;
    const fp = document.createElement('span'); fp.className = 'mono'; fp.textContent = await C.fingerprint(C.b64d(m.public_key));
    li.append(name, fp);
    if (owner && m.user_id !== S.id) {
      const act = (label, fn) => row.append(btn(label, async () => { try { await fn(); await renderMembers(); } catch (e) { toast(e.message); } }));
      ['viewer', 'editor', 'owner'].filter((r) => r !== m.role).forEach((r) => act('Make ' + r, () => api('PUT', `/vaults/${ctx.id}/members/${m.user_id}/role`, { role: r })));
      act('Remove', async () => {
        if (!confirm(`Remove ${m.email}? The vault key will be rotated and every entry re-encrypted.`)) return;
        await removeMember(m.user_id);
      });
    }
    li.append(row); ul.append(li);
  }
  body.append(ul);
}
// Removal re-keys the vault: new key, every entry re-sealed, only remaining members get it. One atomic request.
async function removeMember(uid) {
  const { id, key: oldKey, kv: ov, name } = ctx, newKey = C.rand(32), nv = ov + 1;
  const members = (await api('GET', `/vaults/${id}/members`)).filter((m) => m.user_id !== uid), entries = [];
  for (const e of await api('GET', `/vaults/${id}/entries`)) {
    const plain = await C.decrypt(oldKey, C.b64d(e.blob), C.sentryAad(id, e.id, ov));
    entries.push({ id: e.id, version: e.version, blob: C.b64e(await C.encrypt(newKey, plain, C.sentryAad(id, e.id, nv))) });
  }
  const member_keys = {};
  for (const m of members) member_keys[m.user_id] = C.b64e(await C.wrapFor(C.b64d(m.public_key), newKey, C.keyAad(id, m.user_id, nv)));
  await api('POST', `/vaults/${id}/members/${uid}/remove`, { key_version: nv, member_keys, entries,
    name_blob: C.b64e(await C.encText(newKey, name, C.nameAad(id, nv))) });
  await loadVaults(id); await load(); toast('Member removed and vault key rotated.');
}
$('#btnMembers').onclick = async () => { $('#mErr').textContent = ''; $('#dlgMembers').showModal(); try { await renderMembers(); } catch (e) { toast(e.message); } };
$('#closeMembers').onclick = () => $('#dlgMembers').close();
$('#mAdd').onclick = async () => {
  const err = $('#mErr'); err.textContent = '';
  try {
    const email = $('#mEmail').value.trim(), f = await api('GET', '/users/lookup?email=' + encodeURIComponent(email));
    const pub = C.b64d(f.public_key), fp = await C.fingerprint(pub), want = $('#mFp').value.replace(/\s/g, '').toUpperCase();
    if (want && want !== fp.replace(/ /g, '')) throw new Error('Fingerprint mismatch: nothing was shared. The server returned ' + fp);
    await api('POST', `/vaults/${ctx.id}/members`, { user_id: f.id, role: $('#mRole').value, key_version: ctx.kv,
      wrapped_key: C.b64e(await C.wrapFor(pub, ctx.key, C.keyAad(ctx.id, f.id, ctx.kv))) });
    $('#mEmail').value = $('#mFp').value = '';
    toast(want ? 'Shared.' : 'Shared. Confirm their fingerprint with them: ' + fp);
    await renderMembers();
  } catch (e) { err.textContent = e.message; }
};
$('#delVault').onclick = async () => {
  if (!confirm(`Delete "${ctx.name}" and all its entries for every member?`)) return;
  try { await api('DELETE', '/vaults/' + ctx.id); $('#dlgMembers').close(); await loadVaults(); await load(); } catch (e) { toast(e.message); }
};

// ---- small usability helpers ----
$('#showPw').onchange = (ev) => ['#master', '#confirm'].forEach((s) => ($(s).type = ev.target.checked ? 'text' : 'password'));
function setPwVisible(on) { $('#fPass').type = on ? 'text' : 'password'; $('#togglePw').textContent = on ? 'Hide' : 'Show'; }
$('#togglePw').onclick = () => setPwVisible($('#fPass').type === 'password');
$('#emptyAdd').onclick = () => openEntry(null);

// Copy, then clear the clipboard after 20 s, but ONLY if it still holds what we copied
// (so we never wipe something the user copied afterwards).
let clipTimer = null;
async function copy(text, what) {
  try { await navigator.clipboard.writeText(text); } catch { toast('Copy failed. Allow clipboard access and try again.'); return; }
  toast(`${what} copied. It clears from the clipboard in 20 seconds.`); clearTimeout(clipTimer);
  clipTimer = setTimeout(async () => {
    try { if ((await navigator.clipboard.readText()) !== text) return; } catch { /* cannot read: clear anyway, safer */ }
    navigator.clipboard.writeText('').catch(() => {});
  }, CLIP_MS);
}
