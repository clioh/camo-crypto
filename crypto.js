// WebCrypto primitives for E2EE. Framework-agnostic — same module powers
// the web client today and will power the RN client when its native crypto
// is in place. No runtime deps; all primitives live in `crypto.subtle`.
//
// See docs/encryption.md for algorithm choices and the threat model.

const subtle = globalThis.crypto.subtle;

// ---------- byte helpers ----------

export function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p instanceof Uint8Array ? p : new Uint8Array(p), off);
    off += p.byteLength;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8Encode(s) { return enc.encode(s); }
export function utf8Decode(b) { return dec.decode(b); }

// base64 codecs scoped to bytea round-trips with Supabase (we use base64 for
// JSON wire payloads; Postgres stores raw bytea). Standard alphabet, no url-safe.
export function bytesToBase64(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

export function base64ToBytes(s) {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// ---------- KDF (PBKDF2-SHA256) ----------

// Default KDF params — version this in the user_keys.kdf_params jsonb so an
// upgrade can re-derive transparently on the next login.
export const DEFAULT_KDF_PARAMS = Object.freeze({
  algo: 'pbkdf2',
  hash: 'sha256',
  iters: 600_000,
});

export async function deriveKekFromPassword(password, salt, params = DEFAULT_KDF_PARAMS) {
  if (params.algo !== 'pbkdf2') throw new Error('unsupported kdf');
  const baseKey = await subtle.importKey(
    'raw',
    utf8Encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: params.hash === 'sha256' ? 'SHA-256' : params.hash,
      salt,
      iterations: params.iters,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable — the KEK never leaves the SubtleCrypto sandbox
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}

// ---------- HKDF-SHA256 ----------

export async function hkdfSha256(ikm, info, length = 32, salt = new Uint8Array(0)) {
  const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

// ---------- X25519 ----------

export async function generateX25519KeyPair() {
  return subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
}

export async function exportRawPublicKey(publicKey) {
  const raw = await subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}

export async function exportPkcs8PrivateKey(privateKey) {
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  return new Uint8Array(pkcs8);
}

export async function importRawPublicKey(rawBytes) {
  return subtle.importKey('raw', rawBytes, { name: 'X25519' }, true, []);
}

export async function importPkcs8PrivateKey(pkcs8Bytes) {
  return subtle.importKey('pkcs8', pkcs8Bytes, { name: 'X25519' }, true, ['deriveBits']);
}

export async function ecdhSharedSecret(privateKey, publicKey) {
  const bits = await subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

// ---------- AES-256-GCM ----------

// Imports raw 32-byte material as an AES-GCM key. `extractable` defaults to
// false; callers that need to wrap/export a key must pass true.
export async function importAesKey(rawBytes, { extractable = false, usages = ['encrypt', 'decrypt'] } = {}) {
  return subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, extractable, usages);
}

export async function generateAesKey({ extractable = true, usages = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] } = {}) {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, extractable, usages);
}

export async function aesGcmEncrypt(key, plaintext, { nonce, aad } = {}) {
  const iv = nonce ?? randomBytes(12);
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ct = await subtle.encrypt(params, key, plaintext);
  return { ciphertext: new Uint8Array(ct), nonce: iv };
}

export async function aesGcmDecrypt(key, ciphertext, { nonce, aad } = {}) {
  const params = { name: 'AES-GCM', iv: nonce };
  if (aad) params.additionalData = aad;
  const pt = await subtle.decrypt(params, key, ciphertext);
  return new Uint8Array(pt);
}

// ---------- Identity-key wrap helpers ----------

// Wraps an identity private key (PKCS#8 bytes) under a KEK.
export async function wrapIdentityPrivateKey(kek, pkcs8Bytes) {
  return aesGcmEncrypt(kek, pkcs8Bytes);
}

export async function unwrapIdentityPrivateKey(kek, wrappedBytes, nonce) {
  return aesGcmDecrypt(kek, wrappedBytes, { nonce });
}

// ---------- Conversation-key wrap (X25519 ECDH → HKDF → AES-GCM) ----------

const CONV_KEY_WRAP_INFO_V1 = utf8Encode('camo/conv-key-wrap/v1');

// `recipientPubKeyRaw` is the recipient's identity public key as raw bytes.
// We bind it into the HKDF info string so the same ephemeral keypair can be
// reused across multiple recipients in one chat-request without colliding.
async function deriveConvWrapKek(ephemeralPriv, recipientPub, recipientPubKeyRaw) {
  const shared = await ecdhSharedSecret(ephemeralPriv, recipientPub);
  const info = concatBytes(CONV_KEY_WRAP_INFO_V1, recipientPubKeyRaw);
  const kekBytes = await hkdfSha256(shared, info, 32);
  return importAesKey(kekBytes, { usages: ['encrypt', 'decrypt'] });
}

// Wrap a conversation key (raw 32 bytes) to a recipient's identity pubkey.
// Returns the wrap inputs you need to persist on the server.
export async function wrapConversationKey(ephemeralPriv, recipientPubKey, recipientPubKeyRaw, conversationKeyRaw) {
  const wrapKek = await deriveConvWrapKek(ephemeralPriv, recipientPubKey, recipientPubKeyRaw);
  const aad = concatBytes(CONV_KEY_WRAP_INFO_V1, recipientPubKeyRaw);
  const { ciphertext, nonce } = await aesGcmEncrypt(wrapKek, conversationKeyRaw, { aad });
  return { wrappedKey: ciphertext, nonce };
}

// Recipient-side: given their identity private key + the sender's ephemeral
// public key + the wrapped blob, recover the conversation key bytes.
export async function unwrapConversationKey(myPriv, myPubKeyRaw, ephemeralPub, wrappedKey, nonce) {
  const wrapKek = await deriveConvWrapKek(myPriv, ephemeralPub, myPubKeyRaw);
  const aad = concatBytes(CONV_KEY_WRAP_INFO_V1, myPubKeyRaw);
  return aesGcmDecrypt(wrapKek, wrappedKey, { nonce, aad });
}
