// EFF short wordlist + recovery-passphrase generator.
//
// The wordlist itself lives in `wordlists/effShortV2.js` — the EFF "short
// 2.0" / autocomplete-optimised list (1,296 words, each with a unique
// 3-character prefix). The unique-prefix property powers the type-ahead
// affordance on the recovery-entry screen: once the user has typed three
// characters of a word, we can fill in the rest.
//
// Entropy: log₂(1296) × 12 ≈ 124.20 bits on a 12-word passphrase. The
// filter for hyphen-containing entries is defensive — the v2 list has none,
// but we want the canonicaliser's `-` word separator to stay unambiguous if
// the list is ever swapped.
//
// The wordlist is lazy-loaded — only the registration / forgot-password /
// settings routes import this module, so it never bloats the first-paint
// bundle.

import { WORDLIST as RAW_WORDLIST, WORDLIST_VERSION } from './wordlists/effShortV2.js';

export { WORDLIST_VERSION };

export const WORDLIST = Object.freeze(RAW_WORDLIST.filter((w) => !w.includes('-')));

// Sanity check at module load: every word has a unique 3-character prefix.
// Fails loudly if the wordlist is ever corrupted or swapped for one that
// doesn't satisfy the property the type-ahead UX relies on.
(function assertPrefixesUnique() {
  const seen = new Set();
  for (const w of WORDLIST) {
    const p = w.slice(0, 3);
    if (seen.has(p)) throw new Error(`wordlist prefix collision: ${p}`);
    seen.add(p);
  }
})();

export const PASSPHRASE_WORD_COUNT = 12;

// Generate a recovery passphrase: 12 words, hyphen-separated, each drawn
// uniformly at random from WORDLIST via rejection sampling on
// crypto.getRandomValues — no modulo bias.
export function generateRecoveryPassphrase() {
  const out = new Array(PASSPHRASE_WORD_COUNT);
  for (let i = 0; i < PASSPHRASE_WORD_COUNT; i++) {
    out[i] = WORDLIST[randomIndex(WORDLIST.length)];
  }
  return out.join('-');
}

// Rejection sampling: draw 32 random bits, accept iff the value is below the
// largest multiple of `n` that fits — no skew from `% n` over a non-power-of-two.
function randomIndex(n) {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0xFFFFFFFF / n) * n;
  // Bounded loop in expectation — wasteful draws happen only when n is near
  // a 2^32 boundary, which it never is for our wordlist sizes.
  while (true) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

// Canonicalisation: lowercase, trim, collapse runs of whitespace/hyphens to
// a single hyphen. So "Acid Aged also" and "acid-aged-also" derive the same
// recovery KEK. Idempotent.
export function canonicalisePassphrase(input) {
  return String(input ?? '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '-')
    .replace(/^-|-$/g, '');
}

// Light validation for the recovery-entry input. Returns null on success or
// a short user-friendly error string.
export function validatePassphrase(input) {
  const canon = canonicalisePassphrase(input);
  if (!canon) return 'Recovery passphrase is empty.';
  const words = canon.split('-');
  if (words.length !== PASSPHRASE_WORD_COUNT) {
    return `Recovery passphrase should be ${PASSPHRASE_WORD_COUNT} words.`;
  }
  const set = new Set(WORDLIST);
  for (const w of words) {
    if (!set.has(w)) return `"${w}" is not in the recovery wordlist.`;
  }
  return null;
}

// Returns the first WORDLIST entry whose 3-char prefix matches `prefix`,
// for the registration / recovery type-ahead UI. Case-insensitive.
export function lookupByPrefix(prefix) {
  if (!prefix) return null;
  const p = prefix.slice(0, 3).toLowerCase();
  return WORDLIST.find((w) => w.startsWith(p)) ?? null;
}
