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
  // `forceRefresh` re-fetches the server-side `conversation_keys` row and, on
  // success, re-imports a *fresh* CryptoKey (new object identity) overwriting
  // both caches. The decrypt self-heal path calls this when a row fails to
  // decrypt under the currently-cached key: if a newer key_version exists
  // server-side, this re-syncs it — and the new object identity lets a
  // key-change effect notice and retry the rows that missed. Crucially, a
  // forced refresh that can't reach the server (or whose fetch/unwrap fails)
  // returns the *existing* warm key rather than null — it never destroys a key
  // we already hold (marginal-connectivity invariant). So when forceRefresh
  // returns the same object it was given, the caller knows nothing changed and
  // re-running decrypt is pointless.
  async function ensureConversationKey({ supabase, conversationId, forceRefresh = false } = {}) {
    if (!conversationId) return null;

    // Resolve from the durable warm caches first (in-memory → IDB). This is
    // the value we fall back to no matter what happens below: a conversation
    // key we have *already resolved on this device* must NEVER be discarded
    // just because a refresh couldn't reach the server. This is the
    // marginal-connectivity invariant — decryption of an already-keyed
    // conversation cannot depend on a live network round-trip. (The old
    // forceRefresh path deleted the in-memory key and went straight to the
    // network, so a single `ERR_CONNECTION_RESET` during the decrypt
    // self-heal would null out a working key and blank every bubble.)
    const warm =
      getCachedConversationKey(conversationId) ??
      (await loadConversationKeyFromCache(conversationId).catch(() => null));

    // Steady state: we have a key and the caller didn't demand a re-fetch.
    if (warm && !forceRefresh) return warm;

    // We need the network — either there's no warm key at all, or the caller
    // forced a refresh (the decrypt self-heal suspects the cached key is
    // stale, e.g. a newer key_version exists server-side). If we can't fetch,
    // hand back whatever warm key we have (possibly null) rather than nulling
    // a usable one.
    if (!supabase || !identityPrivKey) return warm;

    let data, error;
    try {
      ({ data, error } = await supabase
        .from('conversation_keys')
        .select('wrapped_key, wrapped_key_nonce, ephemeral_public_key, version')
        .eq('conversation_id', conversationId)
        .eq('user_id', userId)
        .order('version', { ascending: false })
        .limit(1)
        .maybeSingle());
    } catch (_netErr) {
      // Connection reset / timeout / abort — the marginal-network case.
      // Keep the working key in place instead of throwing it away.
      return warm;
    }
    if (error || !data) return warm;
    try {
      // On success this overwrites both caches with a *fresh* CryptoKey (new
      // object identity), which is what lets the chat screen's key-change
      // effect re-run and retry rows that missed under the previous key.
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
      return warm;
    }
  }

  // Batch-warm every conversation key the user holds in a SINGLE request,
  // instead of one `conversation_keys` SELECT per conversation. Used by the
  // inbox to prefetch keys for the whole sidebar so opening any thread is
  // instant. RLS scopes `conversation_keys` to `user_id = me`, so this one
  // query returns exactly the caller's own wrapped keys — bounded by their
  // conversation count, not the whole table.
  //
  // Rows come back ordered (conversation_id asc, version desc) so the first
  // row seen per conversation is its highest version. Already-warm convs (in
  // the in-memory cache) are skipped — no redundant unwrap. Unwrapping is
  // local X25519 work; the only network cost is the lone SELECT. Best-effort:
  // a failed fetch or a single bad row just leaves that conv to resolve
  // lazily on open via ensureConversationKey. Returns { warmed } for callers
  // that want to log/measure.
  async function warmConversationKeys({ supabase } = {}) {
    if (!supabase || !identityPrivKey) return { warmed: 0 };
    let data, error;
    try {
      ({ data, error } = await supabase
        .from('conversation_keys')
        .select('conversation_id, wrapped_key, wrapped_key_nonce, ephemeral_public_key, version')
        .eq('user_id', userId)
        .order('conversation_id', { ascending: true })
        .order('version', { ascending: false }));
    } catch (_netErr) {
      return { warmed: 0 };
    }
    if (error || !data) return { warmed: 0 };
    const seen = new Set();
    let warmed = 0;
    for (const row of data) {
      const cid = row.conversation_id;
      if (!cid || seen.has(cid)) continue; // first row per conv = top version
      seen.add(cid);
      if (convKeyCache.has(cid)) continue; // already warm in memory
      try {
        await unwrapAndCacheConversationKey(cid, {
          wrappedKey: row.wrapped_key instanceof Uint8Array
            ? row.wrapped_key
            : decodeBytea(row.wrapped_key),
          wrappedKeyNonce: row.wrapped_key_nonce instanceof Uint8Array
            ? row.wrapped_key_nonce
            : decodeBytea(row.wrapped_key_nonce),
          ephemeralPublicKeyRaw: row.ephemeral_public_key instanceof Uint8Array
            ? row.ephemeral_public_key
            : decodeBytea(row.ephemeral_public_key),
        });
        warmed++;
      } catch (_e) {
        // Leave this one to resolve lazily on open.
      }
    }
    return { warmed };
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
    warmConversationKeys,
    clearAll,
  };
}
