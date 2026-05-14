// Framework-agnostic key manager. Holds the user's identity private key and
// per-conversation keys in memory, and persists them on disk via a host-
// provided KeyStoreAdapter so a tab reload / cold start doesn't force the
// user to re-enter their password.
//
// On-disk identity-key cache (web): the identity privkey is wrapped under a
// per-device *non-extractable* AES-GCM key generated via WebCrypto. The
// wrapping-key handle and the wrapped blob both live in IDB. The handle is
// origin-bound and non-exportable, so an attacker who exfiltrates the IDB
// bytes alone cannot unwrap. On native, the host adapter is expected to
// route through Keychain/Keystore.
//
// See docs/encryption.md → Key lifecycle → Login.

import {
  randomBytes,
  generateAesKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  importPkcs8PrivateKey,
  exportPkcs8PrivateKey,
  exportRawPublicKey,
  importAesKey,
  importRawPublicKey,
  unwrapConversationKey,
  utf8Encode,
  concatBytes,
} from './crypto.js';

const IDKEY_AAD_V1 = utf8Encode('camo/idkey-cache/v1');
const CONVKEY_AAD_V1 = utf8Encode('camo/convkey-cache/v1');

/**
 * KeyStoreAdapter contract (host-provided):
 *   async getWrappingHandle(): CryptoKey | null
 *   async setWrappingHandle(key: CryptoKey): void
 *   async getWrappedIdentity(): { wrapped: Uint8Array, nonce: Uint8Array } | null
 *   async setWrappedIdentity({ wrapped, nonce }): void
 *   async getWrappedConversationKey(conv_id): { wrapped, nonce } | null
 *   async setWrappedConversationKey(conv_id, { wrapped, nonce }): void
 *   async clearAll(): void
 */

export function createKeyManager({ adapter, userId }) {
  if (!adapter) throw new Error('keyManager requires a KeyStoreAdapter');
  if (!userId) throw new Error('keyManager requires a userId');

  // In-memory state. Cleared on logout.
  let identityPrivKey = null;       // CryptoKey (X25519, deriveBits)
  let identityPubKeyRaw = null;     // Uint8Array
  let wrappingHandle = null;        // CryptoKey (AES-GCM, non-extractable)
  const convKeyCache = new Map();   // conversation_id → CryptoKey (AES-GCM)

  // ----- wrapping handle -----

  async function ensureWrappingHandle() {
    if (wrappingHandle) return wrappingHandle;
    const existing = await adapter.getWrappingHandle();
    if (existing) {
      wrappingHandle = existing;
      return wrappingHandle;
    }
    // Non-extractable AES-GCM key — used via the handle but never exported.
    const handle = await generateAesKey({
      extractable: false,
      usages: ['encrypt', 'decrypt'],
    });
    await adapter.setWrappingHandle(handle);
    wrappingHandle = handle;
    return wrappingHandle;
  }

  // ----- identity key -----

  // Called after login decrypts the server-side wrapped identity key.
  // `privPkcs8` is the plaintext PKCS#8 bytes.
  async function adoptIdentityPrivateKey(privPkcs8, pubRaw) {
    identityPrivKey = await importPkcs8PrivateKey(privPkcs8);
    identityPubKeyRaw = pubRaw;

    // Persist for cold-start: wrap under the per-device handle and stash.
    // pubRaw is stored alongside so a future page load can construct the
    // conversation-key HKDF info string without round-tripping to user_keys.
    const handle = await ensureWrappingHandle();
    const aad = concatBytes(IDKEY_AAD_V1, utf8Encode(userId));
    const { ciphertext, nonce } = await aesGcmEncrypt(handle, privPkcs8, { aad });
    await adapter.setWrappedIdentity({ wrapped: ciphertext, nonce, pubRaw });
    return identityPrivKey;
  }

  // Cold-start path: try to recover the identity privkey from the per-device
  // cache. Returns { privKey, pubRaw } on success, null if there is no cached
  // blob or if the wrapping handle is gone.
  async function loadIdentityFromCache() {
    if (identityPrivKey) return { privKey: identityPrivKey, pubRaw: identityPubKeyRaw };
    const handle = await adapter.getWrappingHandle();
    if (!handle) return null;
    const stored = await adapter.getWrappedIdentity();
    if (!stored) return null;
    const aad = concatBytes(IDKEY_AAD_V1, utf8Encode(userId));
    let pkcs8;
    try {
      pkcs8 = await aesGcmDecrypt(handle, stored.wrapped, { nonce: stored.nonce, aad });
    } catch (_err) {
      // Wrapping handle no longer matches the stored blob (or AAD mismatch — e.g. wrong user).
      // Force a fresh login by wiping the cache.
      await adapter.clearAll();
      return null;
    }
    wrappingHandle = handle;
    identityPrivKey = await importPkcs8PrivateKey(pkcs8);
    identityPubKeyRaw = stored.pubRaw ?? null;
    return { privKey: identityPrivKey, pubRaw: identityPubKeyRaw };
  }

  function getIdentityPrivateKey() {
    return identityPrivKey;
  }

  function getIdentityPublicKeyRaw() {
    return identityPubKeyRaw;
  }

  // Rotate the cached identity privkey on disk after a password change. Server-side
  // wrapping is updated separately; this just refreshes the device-cached copy.
  // `pubRaw` rides along so a cold start can still recover it (the IDB row is
  // a single object, so omitting the field would wipe the previously-cached
  // public key).
  async function refreshCachedIdentity() {
    if (!identityPrivKey) throw new Error('no identity key in memory');
    const handle = await ensureWrappingHandle();
    const pkcs8 = await exportPkcs8PrivateKey(identityPrivKey);
    const aad = concatBytes(IDKEY_AAD_V1, utf8Encode(userId));
    const { ciphertext, nonce } = await aesGcmEncrypt(handle, pkcs8, { aad });
    await adapter.setWrappedIdentity({ wrapped: ciphertext, nonce, pubRaw: identityPubKeyRaw });
  }

  // ----- conversation keys -----

  function getCachedConversationKey(conversationId) {
    return convKeyCache.get(conversationId) ?? null;
  }

  async function adoptConversationKey(conversationId, convKeyRaw) {
    const key = await importAesKey(convKeyRaw, { usages: ['encrypt', 'decrypt'] });
    convKeyCache.set(conversationId, key);
    const handle = await ensureWrappingHandle();
    const aad = concatBytes(CONVKEY_AAD_V1, utf8Encode(conversationId));
    const { ciphertext, nonce } = await aesGcmEncrypt(handle, convKeyRaw, { aad });
    await adapter.setWrappedConversationKey(conversationId, { wrapped: ciphertext, nonce });
    return key;
  }

  async function loadConversationKeyFromCache(conversationId) {
    if (convKeyCache.has(conversationId)) return convKeyCache.get(conversationId);
    const handle = await adapter.getWrappingHandle();
    if (!handle) return null;
    const stored = await adapter.getWrappedConversationKey(conversationId);
    if (!stored) return null;
    const aad = concatBytes(CONVKEY_AAD_V1, utf8Encode(conversationId));
    let raw;
    try {
      raw = await aesGcmDecrypt(handle, stored.wrapped, { nonce: stored.nonce, aad });
    } catch (_err) {
      return null;
    }
    const key = await importAesKey(raw, { usages: ['encrypt', 'decrypt'] });
    convKeyCache.set(conversationId, key);
    return key;
  }

  // Unwrap a server-fetched conversation_keys row using the identity privkey,
  // then cache the result both in memory and on disk.
  async function unwrapAndCacheConversationKey(conversationId, {
    wrappedKey,
    wrappedKeyNonce,
    ephemeralPublicKeyRaw,
  }) {
    if (!identityPrivKey) throw new Error('identity key not loaded');
    const ephemeralPub = await importRawPublicKey(ephemeralPublicKeyRaw);
    const raw = await unwrapConversationKey(
      identityPrivKey,
      identityPubKeyRaw,
      ephemeralPub,
      wrappedKey,
      wrappedKeyNonce,
    );
    return adoptConversationKey(conversationId, raw);
  }

  // ----- lifecycle -----

  async function clearAll() {
    identityPrivKey = null;
    identityPubKeyRaw = null;
    wrappingHandle = null;
    convKeyCache.clear();
    await adapter.clearAll();
  }

  return {
    ensureWrappingHandle,
    adoptIdentityPrivateKey,
    loadIdentityFromCache,
    refreshCachedIdentity,
    getIdentityPrivateKey,
    getIdentityPublicKeyRaw,
    adoptConversationKey,
    getCachedConversationKey,
    loadConversationKeyFromCache,
    unwrapAndCacheConversationKey,
    clearAll,
  };
}
