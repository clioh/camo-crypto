# camo-crypto

Cryptographic primitives used by [Camo Chat](https://camo-chat.vercel.app)
for end-to-end encrypted messaging. Published under EAR §742.15(b) to
satisfy US export-control obligations on E2EE messaging applications.

This repository is a **mirror** — the upstream source of truth is the
[Camo Chat](https://camo-chat.com) main codebase. See "Mirror
mechanics" below.

## Export classification

```
This source code is publicly available encryption source code released
under the license terms in LICENSE. It is classified as ECCN 5D002 and
is subject to the US Export Administration Regulations (EAR) at 15 CFR
Parts 730-774. Pursuant to 15 CFR §742.15(b), notification of public
availability was provided to the US Bureau of Industry and Security
(BIS) and the National Security Agency (NSA) on pending — see issue #1,
citing this repository URL. No further authorization is required for
export or reexport so long as the source code remains publicly available
and unmodified relative to this repository.

Re-publishing, forking, or otherwise mirroring this code to a new URL
triggers a separate notification obligation for the party doing so.
```

## Cryptographic functionality

All algorithms are published standards. The modules invoke the platform
Web Crypto API (W3C Recommendation) on the web and equivalent native
crypto APIs on mobile — they are bindings and protocol glue, not
algorithm implementations.

| Primitive          | Standard                                           |
|--------------------|----------------------------------------------------|
| PBKDF2-SHA256      | RFC 8018 (PBKDF2), FIPS 198-1 (underlying HMAC)    |
| HKDF-SHA256        | RFC 5869                                           |
| AES-256-GCM        | NIST SP 800-38D                                    |
| X25519             | RFC 7748                                           |
| ECDH on X25519     | RFC 7748                                           |

No cryptanalysis, key recovery, or other restricted functions. No
proprietary or non-standard cryptography.

## Public API surface

### `crypto.js`

Byte helpers (`randomBytes`, `concatBytes`, `bytesEqual`, `utf8Encode`,
`utf8Decode`, `bytesToBase64`, `base64ToBytes`); KDFs
(`deriveKekFromPassword`, `hkdfSha256`); X25519 keypair generation,
export/import (`generateX25519KeyPair`, `exportRawPublicKey`,
`exportPkcs8PrivateKey`, `importRawPublicKey`, `importPkcs8PrivateKey`,
`ecdhSharedSecret`); AES-GCM (`importAesKey`, `generateAesKey`,
`aesGcmEncrypt`, `aesGcmDecrypt`); higher-level wrap helpers for
identity keys and per-conversation keys
(`wrapIdentityPrivateKey`, `unwrapIdentityPrivateKey`,
`wrapConversationKey`, `unwrapConversationKey`).

### `keyManager.js`

`createKeyManager({ adapter, userId })` returns a stateful in-memory key
manager. The host supplies a `KeyStoreAdapter` that persists the
wrapping handle + wrapped identity key + wrapped conversation keys to
whatever local store is available (IndexedDB on web, Keychain/Keystore
on native). The wrapping handle is a non-extractable AES-GCM key
generated via WebCrypto so a stolen on-disk blob alone cannot be
unwrapped without origin/sandbox access.

### `wordlist.js`

`generateRecoveryPassphrase()`, `canonicalisePassphrase(input)`,
`validatePassphrase(input)`, `lookupByPrefix(prefix)`, plus the
`WORDLIST` array and `WORDLIST_VERSION` re-exports.

A 12-word recovery passphrase drawn uniformly from a 1,296-word list
gives log₂(1296) × 12 ≈ 124.20 bits of entropy. Rejection sampling on
`crypto.getRandomValues` — no modulo bias.

## Wordlist attribution

`wordlists/effShortV2.js` is an embedding of the **EFF Short Wordlist
v2.0 (autocomplete-optimised)**:

> © Electronic Frontier Foundation, licensed CC BY 3.0 US.
> Source: https://www.eff.org/dice
> Direct link: https://www.eff.org/files/2016/09/08/eff_short_wordlist_2_0.txt

The 1,296-word list is reproduced verbatim. The unique 3-character
prefix property — every word has a distinct 3-character prefix — is
what powers the type-ahead affordance on Camo Chat's recovery-entry
screen.

## Consumption

The modules are zero-dependency ESM and run on any environment that
exposes the Web Crypto API (`globalThis.crypto.subtle`):

- Browsers (all evergreens): native.
- Node.js ≥ 18: native.
- React Native: requires a Web Crypto polyfill that includes
  X25519 + AES-GCM + HKDF + PBKDF2 (e.g. `expo-crypto` + a SubtleCrypto
  shim that proxies to native).

```js
import { aesGcmEncrypt, deriveKekFromPassword } from 'camo-crypto/crypto';
import { createKeyManager } from 'camo-crypto/keyManager';
import { generateRecoveryPassphrase } from 'camo-crypto/wordlist';
```

Or via the umbrella entry:

```js
import * as crypto from 'camo-crypto';
```

## License

Apache License 2.0 — see `LICENSE`. The patent grant matters for crypto
code: it forecloses patent ambush against downstream users of these
specific implementations.

## Mirror mechanics

This repository is updated by a script in the upstream Camo Chat
codebase. The upstream `src/core/{crypto,keyManager,wordlist}.js`
+ `wordlists/effShortV2.js` are copied here verbatim on each release;
the static files (`README.md`, `LICENSE`, `package.json`, `index.js`)
are owned by the upstream `compliance/camo-crypto/` directory and
copied alongside.

Commit messages on this repo are of the form `Sync from camo-chat@<sha>`
and reference the upstream commit. The upstream repo records the
resulting commit SHA + per-file SHA-256s in `compliance/camo-crypto.lock`,
and a pre-deploy check on the upstream side blocks shipping if the
deployed bytes diverge from what was last published here. That check is
how §742.15(b)'s "publicly available source code matches the shipped
binary" requirement is mechanically enforced.

Patches against the cryptographic primitives are accepted upstream, not
on this mirror. Patches against the README, LICENSE, or other static
files of this repo are likewise accepted upstream in
`compliance/camo-crypto/`.
