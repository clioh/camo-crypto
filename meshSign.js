// Ed25519 mesh-envelope signing identity.
//
// The signing key is DERIVED from the user's X25519 identity private key via
// domain-separated HKDF — no new secret is generated, stored, or wrapped. The
// 32-byte Ed25519 seed is recomputed on demand from the identity PKCS#8 bytes,
// so every device that unwraps the identity key derives the same signing key,
// and every rotation of the identity key rotates the signing key with it.
//
// Why a derived key rather than an independently-wrapped one: it adds zero
// wrapped columns and touches none of the password/recovery rotation paths in
// userKeys.js. Reusing one root for two algorithms is safe *because* we
// domain-separate with a distinct HKDF info label and never reuse the raw
// X25519 scalar as an Ed25519 scalar — the HKDF output is an independent seed.
//
// Why @noble/curves rather than crypto.subtle: react-native-quick-crypto's
// subtle Ed25519 support is unverified, and subtle cannot import a private key
// from a raw 32-byte seed (it wants PKCS#8 DER). noble is pure-JS, audited,
// identical on web + RN, and takes the seed directly. It is isolated to this
// one module so core/crypto.js stays a zero-dependency crypto.subtle module.
//
// EAR-mirrored crypto: this file is published to the public camo-crypto repo
// (scripts/crypto-sync.mjs + the lock). See docs/mesh.md → Crypto additions.

import { ed25519 } from '@noble/curves/ed25519';
import { hkdfSha256, utf8Encode } from './crypto.js';

// Domain-separation label. NEVER change this string: it is mixed into the HKDF
// info, so changing it would change every user's derived signing key and
// invalidate every signing public key already published to user_keys.
const MESH_SIGN_INFO_V1 = utf8Encode('camo/mesh-sign-ed25519/v1');

// Derive the raw 32-byte Ed25519 seed (== the noble secret key) from the
// identity private key's PKCS#8 bytes. Deterministic per identity, per device.
export async function deriveMeshSigningSeed(identityPkcs8) {
  return hkdfSha256(identityPkcs8, MESH_SIGN_INFO_V1, 32);
}

// Derive the signing keypair. Returns { seed, publicKeyRaw } — both 32 bytes.
// `seed` is the private half (keep in memory only); `publicKeyRaw` is what we
// publish to user_keys.identity_signing_public_key.
export async function deriveMeshSigningKeyPair(identityPkcs8) {
  const seed = await deriveMeshSigningSeed(identityPkcs8);
  const publicKeyRaw = ed25519.getPublicKey(seed);
  return { seed, publicKeyRaw };
}

// Detached 64-byte Ed25519 signature over `message` (Uint8Array).
export function signWithMeshKey(seed, message) {
  return ed25519.sign(message, seed);
}

// Verify a detached signature. Returns a boolean; never throws (a malformed
// public key or signature is just an invalid signature from the relay's POV).
export function verifyMeshSignature(publicKeyRaw, signature, message) {
  try {
    return ed25519.verify(signature, message, publicKeyRaw);
  } catch {
    return false;
  }
}
