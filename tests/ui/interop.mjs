// Runs the REAL browser crypto module under Node. stdin: JSON job, stdout: JSON result.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import * as C from '../../pwvault_server/static/crypto.js';
const require = createRequire(import.meta.url);
const { argon2id } = require('../../pwvault_server/static/vendor/argon2.umd.min.js');

const job = JSON.parse(readFileSync(0, 'utf8'));
const { encKey, authKey } = await C.deriveKeys(argon2id, job.password, C.b64d(job.salt), job.kdf);
const vaultKey = await C.decrypt(encKey, C.b64d(job.wrapped_key), C.WRAP_AAD);
const opened = await C.open(vaultKey, job.row);
const id = '11111111-2222-4333-8444-555555555555';
const sealed = await C.seal(vaultKey, id, { site: 'from-js.example', username: 'jsuser', password: 'pässwörd-日本', notes: 'n' });
const pw = C.generatePassword(24);
// --- sharing: Python-made keys/blobs must open here, and ours must open in Python ---
const sh = job.share, shPriv = C.b64d(sh.priv), shPub = C.b64d(sh.pub);
const unwrapped = await C.unwrap(shPriv, C.b64d(sh.wrapped), C.keyAad('v', 'u', 3));
const jsKp = await C.generateKeypair();
const share = { unwrapped: C.b64e(unwrapped), pubFromPriv: C.b64e(await C.publicFromPrivate(shPriv)),
  fp: await C.fingerprint(shPub), jsPriv: C.b64e(jsKp.priv), jsPub: C.b64e(jsKp.pub),
  wrappedForPy: C.b64e(await C.wrapFor(shPub, te_('from-js-vault-key'), C.keyAad('v', 'u', 3))) };
function te_(t) { return new TextEncoder().encode(t); }
const sha = await C.sha1Split('password');
const count = C.countInRange('0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n' + sha.suffix + ':9545824\r\n', sha.suffix);
console.log(JSON.stringify({ share, sha, count, authKey: C.b64e(authKey), opened, id, sealed, pw, strong: C.strength(pw).score,
  weak: C.strength('password1').score }));
