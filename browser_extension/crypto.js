// Client-side crypto. Mirrors pwvault/remote.py byte-for-byte so the web UI and
// the Python client can open each other's vaults. Nothing here touches the network.
const te = new TextEncoder(), td = new TextDecoder();
export const b64e = (u8) => {
  let raw = '';
  for (let i = 0; i < u8.length; i += 0x8000) raw += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(raw);
};
export const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
export const WRAP_AAD = 'pwvault:remote-vault-key:v1';
export const entryAad = (id) => 'pwvault:entry:v1:' + id;

// master password --Argon2id--> master key --HKDF--> enc_key (stays here) + auth_key (sent)
export async function deriveKeys(argon2id, password, salt, kdf) {
  if (!Number.isInteger(kdf.time_cost) || kdf.time_cost < 1 || kdf.time_cost > 10 ||
      !Number.isInteger(kdf.memory_cost_kib) || kdf.memory_cost_kib < 8 || kdf.memory_cost_kib > 524288 ||
      !Number.isInteger(kdf.parallelism) || kdf.parallelism < 1 || kdf.parallelism > 16 ||
      kdf.memory_cost_kib < 8 * kdf.parallelism) {
    throw new Error('The server supplied unsupported key-derivation parameters.');
  }
  const master = await argon2id({
    password, salt, parallelism: kdf.parallelism, iterations: kdf.time_cost,
    memorySize: kdf.memory_cost_kib, hashLength: 32, outputType: 'binary' });
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  const hk = async (label) => new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(label) }, base, 256));
  return { encKey: await hk('pwvault:v3:enc'), authKey: await hk('pwvault:v3:auth') };
}

export const RECOVERY_KEY_AAD = 'pwvault:recovery:v1:vault-key';
export const RECOVERY_PRIVATE_AAD = 'pwvault:recovery:v1:private-key';
export async function deriveRecoveryKeys(recoverySecret, salt) {
  if (recoverySecret.length !== 32 || salt.length !== 16) throw new Error('Invalid recovery key.');
  const base = await crypto.subtle.importKey('raw', recoverySecret, 'HKDF', false, ['deriveBits']);
  const hk = async (label) => new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(label) }, base, 256));
  return { encKey: await hk('pwvault:recovery:v1:enc'), authKey: await hk('pwvault:recovery:v1:auth') };
}

const aes = (k, use) => crypto.subtle.importKey('raw', k, 'AES-GCM', false, [use]);

export async function encrypt(key, data, aad) {          // output = nonce || ciphertext+tag
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode(aad) }, await aes(key, 'encrypt'), data);
  return Uint8Array.from([...iv, ...new Uint8Array(ct)]);
}

export async function decrypt(key, blob, aad) {          // throws if wrong key / tampered
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, 12), additionalData: te.encode(aad) },
    await aes(key, 'decrypt'), blob.slice(12)));
}

export const seal = async (vaultKey, id, e) => b64e(await encrypt(vaultKey,
  te.encode(JSON.stringify({ type: e.type || 'login', site: e.site, username: e.username,
    password: e.password, notes: e.notes, fields: e.fields || {}, attachments: e.attachments || [] })),
  entryAad(id)));

export async function open(vaultKey, row) {
  const d = JSON.parse(td.decode(await decrypt(vaultKey, b64d(row.blob), entryAad(row.id))));
  return { type: 'login', username: '', password: '', notes: '', fields: {}, attachments: [], ...d, id: row.id, version: row.version };
}

// CSPRNG password generator (rejection sampling avoids modulo bias)
const SETS = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!@#$%^&*()-_=+[]{};:,.?'];
function pick(n) {
  const limit = 256 - (256 % n);
  for (;;) { const b = rand(1)[0]; if (b < limit) return b % n; }
}
export function generatePassword(len = 20) {
  const all = SETS.join('');
  const out = SETS.map((s) => s[pick(s.length)]);
  while (out.length < len) out.push(all[pick(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = pick(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('');
}

// Rough strength estimate (entropy with penalties). A real deployment should
// use zxcvbn; this keeps the app dependency-free.
export function strength(pw) {
  if (!pw) return { score: 0, label: '' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 28;
  let bits = pw.length * Math.log2(pool || 1) * Math.min(1, new Set(pw).size / (pw.length * 0.7));
  if (/password|passw0rd|qwert|azert|admin|letmein|welcome|1234|abcd|algerie/i.test(pw)) bits *= 0.5;
  const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { score, label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][score] };
}

// HIBP k-anonymity: only `prefix` (5 hex chars) is ever sent. SHA-1 is required by that API.
export async function sha1Split(pw) {
  const h = [...new Uint8Array(await crypto.subtle.digest('SHA-1', te.encode(pw)))]
    .map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return { prefix: h.slice(0, 5), suffix: h.slice(5) };
}
export function countInRange(text, suffix) {
  for (const line of text.split('\n')) { const [s, c] = line.trim().split(':'); if (s === suffix) return parseInt(c || '0', 10); }
  return 0;
}

// ---- sharing: X25519 + HKDF + AES-GCM (ECIES). Byte-compatible with pwvault/sharing.py ----
const subtle = crypto.subtle;
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
export const PRIV_AAD = 'pwvault:private-key:v1';
export const keyAad = (v, u, n) => `pwvault:vault-key:v1:${v}:${u}:${n}`;
export const sentryAad = (v, e, n) => `pwvault:shared-entry:v1:${v}:${e}:${n}`;
export const nameAad = (v, n) => `pwvault:vault-name:v1:${v}:${n}`;
export const encText = (k, t, aad) => encrypt(k, te.encode(t), aad);
export const decText = async (k, b, aad) => td.decode(await decrypt(k, b, aad));
const cat = (...a) => Uint8Array.from(a.flatMap((x) => [...x]));
// WebCrypto cannot import a raw X25519 private key, so wrap the 32 bytes in a PKCS#8 header.
const importPriv = (raw) => subtle.importKey('pkcs8', cat(PKCS8, raw), 'X25519', true, ['deriveBits']);
const importPub = (raw) => subtle.importKey('raw', raw, 'X25519', true, []);

export async function generateKeypair() {
  const kp = await subtle.generateKey('X25519', true, ['deriveBits']);
  return { priv: new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey)).slice(-32),
           pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}
export async function publicFromPrivate(raw) {
  const { x } = await subtle.exportKey('jwk', await importPriv(raw));
  return b64d(x.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(x.length / 4) * 4, '='));
}
async function shareKey(priv, pub, ephPub, recipPub) {
  const shared = await subtle.deriveBits({ name: 'X25519', public: await importPub(pub) }, await importPriv(priv), 256);
  const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: cat(ephPub, recipPub),
    info: te.encode('pwvault:share:v1') }, base, 256));
}
export async function wrapFor(recipPub, secret, aad) {
  const eph = await generateKeypair();
  return cat(eph.pub, await encrypt(await shareKey(eph.priv, recipPub, eph.pub, recipPub), secret, aad));
}
export async function unwrap(priv, blob, aad) {
  const ephPub = blob.slice(0, 32);
  return decrypt(await shareKey(priv, ephPub, ephPub, await publicFromPrivate(priv)), blob.slice(32), aad);
}
export async function fingerprint(pub) {
  const h = [...new Uint8Array(await subtle.digest('SHA-256', pub))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return h.slice(0, 32).toUpperCase().match(/.{4}/g).join(' ');
}
export const sealShared = async (key, vid, id, kv, e) => b64e(await encText(key,
  JSON.stringify({ type: e.type || 'login', site: e.site, username: e.username, password: e.password,
    notes: e.notes, fields: e.fields || {}, attachments: e.attachments || [] }), sentryAad(vid, id, kv)));
export async function openShared(key, vid, row) {
  const d = JSON.parse(await decText(key, b64d(row.blob), sentryAad(vid, row.id, row.key_version)));
  return { type: 'login', username: '', password: '', notes: '', fields: {}, attachments: [], ...d, id: row.id, version: row.version };
}
