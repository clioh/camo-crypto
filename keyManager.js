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
  generateX25519KeyPair,
  aesGcmEncrypt,
  aesGcmDecrypt,
  importPkcs8PrivateKey,
  exportPkcs8PrivateKey,
  exportRawPublicKey,
  importAesKey,
  importRawPublicKey,
  wrapConversationKey,
  unwrapConversationKey,
  utf8Encode,
  concatBytes,
} from './crypto.js';
import { unwrapIdentityWithPassword, decodeBytea } from './userKeys.js';

const IDKEY_AAD_V1 = utf8Encode('camo/idkey-cache/v1');
const CONVKEY_AAD_V1 = utf8Encode('camo/convkey-cache/v1');

/**
 * KeyStoreAdapter contract (host-provided). Setters take an *explicit, complete*
 * field set — there is no merge with the existing row, so a caller that omits
 * a field would silently null it. Hosts MUST runtime-assert each required
 * field; see src/web/platform/keyStore.js for the web binding.
 *
 *   async getWrappingHandle(): CryptoKey | null
 *   async setWrappingHandle(handle: CryptoKey): void
 *   async getWrappedIdentity(): { wrapped: Uint8Array, nonce: Uint8Array, pubRaw: Uint8Array } | null
 *   async setWrappedIdentity({ wrapped, nonce, pubRaw }): void
 *   async getWrappedConversationKey(conv_id): { wrapped: Uint8Array, nonce: Uint8Array } | null
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

  // Materialise the identity privkey, trying every warm path before falling
  // back to a server-side unwrap. Used by callers that need pkcs8 bytes for
  // re-wrapping (password change, identity-key reset, accept-chat-request
  // fast-path on a cold device, etc.) so the "is the key here?" decision lives
  // in one place. Phase 2 carry-forward #2 — see docs/encryption.md.
  //
  //   - in-memory: cheapest, always tried first
  //   - IDB cold-start cache: free, no network
  //   - unwrapIdentityWithPassword: only if `password` is supplied
  //
  // Returns one of:
  //   { ok: true, pkcs8: Uint8Array, pubRaw: Uint8Array,
  //     source: 'memory' | 'cache' | 'server' }
  //   { ok: false, reason: 'needs-password' | 'wrong-password' | 'missing-row' | 'export-failed' }
  async function ensureIdentityKey({ supabase, userId: callerUserId, password } = {}) {
    const uid = callerUserId || userId;

    if (identityPrivKey) {
      try {
        const pkcs8 = await exportPkcs8PrivateKey(identityPrivKey);
        return { ok: true, pkcs8, pubRaw: identityPubKeyRaw, source: 'memory' };
      } catch (_e) {
        // Fall through to next path. extractable:false would land here, but
        // we always import with extractable:true today.
      }
    }

    const cached = await loadIdentityFromCache().catch(() => null);
    if (cached && identityPrivKey) {
      try {
        const pkcs8 = await exportPkcs8PrivateKey(identityPrivKey);
        return { ok: true, pkcs8, pubRaw: identityPubKeyRaw, source: 'cache' };
      } catch (_e) {
        // Same caveat as above.
      }
    }

    if (!password || !supabase) {
      return { ok: false, reason: 'needs-password' };
    }
    const r = await unwrapIdentityWithPassword(supabase, uid, password);
    if (r.error) {
      // unwrapIdentityWithPassword conflates "no row" and "wrong password" —
      // surface the more useful default and let the caller refine.
      return { ok: false, reason: 'wrong-password' };
    }
    await adoptIdentityPrivateKey(r.pkcs8, r.pubRaw);
    return { ok: true, pkcs8: r.pkcs8, pubRaw: r.pubRaw, source: 'server' };
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

  // Sender-side: build a fresh conversation key + wraps for both parties,
  // for a chat-request send. Returns the raw conv key alongside the wire-
  // format wrap columns so the caller can both (a) ship the wraps in the
  // chat_requests insert and (b) keep the raw conv key locally to encrypt
  // the first messages without waiting for the recipient's accept.
  //
  // Reuses a single ephemeral keypair across both wraps — the HKDF info
  // string mixes in each recipient's identity pubkey, so the resulting
  // KEKs are independent. See docs/encryption.md → Conversation key creation.
  async function prepareWrappedConversationKey({ recipientPubKeyRaw }) {
    if (!(recipientPubKeyRaw instanceof Uint8Array)) {
      throw new Error('recipientPubKeyRaw must be a Uint8Array');
    }
    if (!identityPubKeyRaw) {
      throw new Error('sender identity public key not loaded');
    }
    const convKeyRaw = randomBytes(32);
    const eph = await generateX25519KeyPair();
    const ephemeralPublicKeyRaw = await exportRawPublicKey(eph.publicKey);
    const recipientPub = await importRawPublicKey(recipientPubKeyRaw);
    const senderPub = await importRawPublicKey(identityPubKeyRaw);
    const wrappedForRecipient = await wrapConversationKey(
      eph.privateKey, recipientPub, recipientPubKeyRaw, convKeyRaw,
    );
    const wrappedForSender = await wrapConversationKey(
      eph.privateKey, senderPub, identityPubKeyRaw, convKeyRaw,
    );
    return {
      convKeyRaw,
      ephemeralPublicKeyRaw,
      wrappedForRecipient: wrappedForRecipient.wrappedKey,
      wrappedForRecipientNonce: wrappedForRecipient.nonce,
      wrappedForSender: wrappedForSender.wrappedKey,
      wrappedForSenderNonce: wrappedForSender.nonce,
    };
  }

  // Unwrap a server-fetched wrapped conversation key using the identity
  // privkey, returning the raw 32-byte key bytes. The caller can either feed
  // those bytes into adoptConversationKey (once a conversation_id is known)
  // or use them transiently. Kept separate from caching so the accept-chat-
  // request fast-path can decrypt *before* the RPC returns the new
  // conversation_id (see src/web/screens/requests.js).
  async function unwrapConversationKeyMaterial({
    wrappedKey,
    wrappedKeyNonce,
    ephemeralPublicKeyRaw,
  }) {
    if (!identityPrivKey) throw new Error('identity key not loaded');
    const ephemeralPub = await importRawPublicKey(ephemeralPublicKeyRaw);
    return unwrapConversationKey(
      identityPrivKey,
      identityPubKeyRaw,
      ephemeralPub,
      wrappedKey,
      wrappedKeyNonce,
    );
  }

  // Unwrap a server-fetched conversation_keys row using the identity privkey,
  // then cache the result both in memory and on disk.
  async function unwrapAndCacheConversationKey(conversationId, material) {
    const raw = await unwrapConversationKeyMaterial(material);
    return adoptConversationKey(conversationId, raw);
  }

  // Read-path ladder: resolve the AES-GCM conversation key for a conv id.
  //   1. in-memory cache         (warmest, free)
  //   2. IDB cold-start cache    (free, no network)
  //   3. server fetch + unwrap   (single SELECT; populates both caches)
  // Returns the AES-GCM CryptoKey on success, or null if the row is missing,
  // the identity privkey isn't loaded, or unwrapping fails. The chat-route
  // composer-gate (docs/encryption.md → Conversation-key prerequisite for
  // compose) uses the null return to render the "connecting securely…"
  // disabled-composer state. We deliberately do not throw — every caller
  // would just have to catch and surface the same state.
  //
  // `forceRefresh` skips both warm caches and re-fetches the server-side
  // `conversation_keys` row, re-importing a *fresh* CryptoKey (new object
  // identity) and overwriting both caches. The decrypt self-heal path calls
  // this when a row fails to decrypt under the currently-cached key: if the
  // cache somehow holds a stale/wrong key for the conversation, this is what
  // re-syncs it — and the new object identity lets a key-change effect notice
  // and retry the rows that missed. A no-op-equivalent (same bytes) refresh is
  // still cheap and safe.
  async function ensureConversationKey({ supabase, conversationId, forceRefresh = false } = {}) {
    if (!conversationId) return null;
    if (!forceRefresh) {
      const cached = getCachedConversationKey(conversationId);
      if (cached) return cached;
      const fromCache = await loadConversationKeyFromCache(conversationId).catch(() => null);
      if (fromCache) return fromCache;
    } else {
      // Drop the warm in-memory handle so the re-adopt below installs a fresh
      // CryptoKey rather than returning the same (possibly wrong) object.
      convKeyCache.delete(conversationId);
    }
    if (!supabase) return null;
    if (!identityPrivKey) return null;
    const { data, error } = await supabase
      .from('conversation_keys')
      .select('wrapped_key, wrapped_key_nonce, ephemeral_public_key, version')
      .eq('conversation_id', conversationId)
      .eq('user_id', userId)
      .order('version', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error || !data) return null;
    try {
      return await unwrapAndCacheConversationKey(conversationId, {
        wrappedKey: data.wrapped_key instanceof Uint8Array
          ? data.wrapped_key
          : decodeBytea(data.wrapped_key),
        wrappedKeyNonce: data.wrapped_key_nonce instanceof Uint8Array
          ? data.wrapped_key_nonce
          : decodeBytea(data.wrapped_key_nonce),
        ephemeralPublicKeyRaw: data.ephemeral_public_key instanceof Uint8Array
          ? data.ephemeral_public_key
          : decodeBytea(data.ephemeral_public_key),
      });
    } catch (_e) {
      return null;
    }
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
    ensureIdentityKey,
    adoptConversationKey,
    getCachedConversationKey,
    loadConversationKeyFromCache,
    prepareWrappedConversationKey,
    unwrapConversationKeyMaterial,
    unwrapAndCacheConversationKey,
    ensureConversationKey,
    clearAll,
  };
}
