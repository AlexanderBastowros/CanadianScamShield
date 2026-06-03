/**
 * lib/homoglyph.js
 * Unicode homoglyph normalization and Levenshtein edit-distance utilities.
 *
 * Runs in Node.js and in a Manifest V3 service worker — no DOM, no Chrome APIs.
 *
 * Exported functions:
 *   normalizeHomoglyphs(str)                       → normalized ASCII string
 *   levenshtein(a, b)                              → integer edit distance
 *   isDomainLookalike(input, candidate, maxDist=2) → boolean
 */

// ---------------------------------------------------------------------------
// Homoglyph map
// Each key is a Unicode codepoint (or character) that visually resembles the
// ASCII character in its value.  We cover:
//   • Cyrillic confusables (common in phishing domains)
//   • Greek confusables
//   • Miscellaneous visually similar characters
//   • Full-width Latin (U+FF01–U+FF5E) is handled programmatically below.
// ---------------------------------------------------------------------------
const HOMOGLYPH_MAP = {
  // ── Cyrillic ──────────────────────────────────────────────────────────────
  'а': 'a', // а  CYRILLIC SMALL LETTER A
  'е': 'e', // е  CYRILLIC SMALL LETTER IE
  'о': 'o', // о  CYRILLIC SMALL LETTER O
  'р': 'p', // р  CYRILLIC SMALL LETTER ER
  'с': 'c', // с  CYRILLIC SMALL LETTER ES
  'х': 'x', // х  CYRILLIC SMALL LETTER HA
  'у': 'y', // у  CYRILLIC SMALL LETTER U
  'і': 'i', // і  CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
  'ѕ': 's', // ѕ  CYRILLIC SMALL LETTER DZE
  'ԁ': 'd', // ԁ  CYRILLIC SMALL LETTER KOMI DE
  'ь': 'b', // ь  CYRILLIC SMALL LETTER SOFT SIGN  (looks like b)
  'А': 'a', // А  CYRILLIC CAPITAL LETTER A
  'Е': 'e', // Е  CYRILLIC CAPITAL LETTER IE
  'О': 'o', // О  CYRILLIC CAPITAL LETTER O
  'Р': 'p', // Р  CYRILLIC CAPITAL LETTER ER
  'С': 'c', // С  CYRILLIC CAPITAL LETTER ES
  'Х': 'x', // Х  CYRILLIC CAPITAL LETTER HA
  'У': 'y', // У  CYRILLIC CAPITAL LETTER U
  'І': 'i', // І  CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
  'В': 'b', // В  CYRILLIC CAPITAL LETTER VE (looks like B)
  'Н': 'h', // Н  CYRILLIC CAPITAL LETTER EN  (looks like H)
  'М': 'm', // М  CYRILLIC CAPITAL LETTER EM

  // ── Greek ─────────────────────────────────────────────────────────────────
  'α': 'a', // α  GREEK SMALL LETTER ALPHA
  'ο': 'o', // ο  GREEK SMALL LETTER OMICRON
  'ε': 'e', // ε  GREEK SMALL LETTER EPSILON
  'ν': 'v', // ν  GREEK SMALL LETTER NU
  'ρ': 'p', // ρ  GREEK SMALL LETTER RHO
  'τ': 't', // τ  GREEK SMALL LETTER TAU
  'Α': 'a', // Α  GREEK CAPITAL LETTER ALPHA
  'Ο': 'o', // Ο  GREEK CAPITAL LETTER OMICRON
  'Ε': 'e', // Ε  GREEK CAPITAL LETTER EPSILON
  'Ν': 'n', // Ν  GREEK CAPITAL LETTER NU
  'Ρ': 'p', // Ρ  GREEK CAPITAL LETTER RHO
  'Τ': 't', // Τ  GREEK CAPITAL LETTER TAU

  // ── Miscellaneous visually similar ───────────────────────────────────────
  'ℓ': 'l', // ℓ  SCRIPT SMALL L
  'ı': 'i', // ı  LATIN SMALL LETTER DOTLESS I
  'ƥ': 'p', // ƥ  LATIN SMALL LETTER P WITH HOOK
  'ɡ': 'g', // ɡ  LATIN SMALL LETTER SCRIPT G
  'ɯ': 'm', // ɯ  LATIN SMALL LETTER TURNED M
};

/**
 * normalizeHomoglyphs(str)
 *
 * Lowercases the input then replaces every character that is a known Unicode
 * homoglyph with its ASCII equivalent.  Full-width Latin characters in the
 * range U+FF01–U+FF5E are mapped to their ASCII counterparts by subtracting
 * 0xFEE0 from their codepoint.
 *
 * @param {string} str
 * @returns {string}
 */
export function normalizeHomoglyphs(str) {
  if (typeof str !== 'string') return str;

  // Lowercase first so the map keys for capital Cyrillic/Greek are hit.
  // We keep a separate pass so the map can also contain uppercase entries
  // for any case-sensitive Unicode codepoints not affected by toLowerCase.
  const lower = str.toLowerCase();

  let result = '';
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i];
    const cp = lower.codePointAt(i);

    // Full-width Latin: U+FF01 (！) through U+FF5E (～)
    // Subtract 0xFEE0 to get the ASCII equivalent.
    if (cp >= 0xFF01 && cp <= 0xFF5E) {
      result += String.fromCodePoint(cp - 0xFEE0);
      continue;
    }

    // Explicit homoglyph map lookup.
    if (HOMOGLYPH_MAP[ch] !== undefined) {
      result += HOMOGLYPH_MAP[ch];
      continue;
    }

    result += ch;
  }

  return result;
}

/**
 * levenshtein(a, b)
 *
 * Standard iterative dynamic-programming edit distance.
 * Time O(|a|·|b|), space O(|b|) using two rows.
 *
 * Edge cases:
 *   levenshtein('', 'abc') === 3
 *   levenshtein('kitten', 'sitting') === 3
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshtein(a, b) {
  // Fast-path: identical strings
  if (a === b) return 0;

  const la = a.length;
  const lb = b.length;

  // Fast-path: one string is empty
  if (la === 0) return lb;
  if (lb === 0) return la;

  // We iterate over rows of a and maintain only two rows (prev / curr).
  let prev = new Array(lb + 1);
  let curr = new Array(lb + 1);

  // Initialize the first row: cost of deleting 0..lb characters from b.
  for (let j = 0; j <= lb; j++) prev[j] = j;

  for (let i = 1; i <= la; i++) {
    curr[0] = i; // cost of deleting i characters from a

    for (let j = 1; j <= lb; j++) {
      const substitutionCost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,                    // insertion
        prev[j] + 1,                         // deletion
        prev[j - 1] + substitutionCost       // substitution
      );
    }

    // Swap rows for the next iteration
    [prev, curr] = [curr, prev];
  }

  return prev[lb];
}

/**
 * isDomainLookalike(input, candidate, maxDistance = 2)
 *
 * Returns true if the homoglyph-normalized version of `input` is within
 * `maxDistance` edit operations of the homoglyph-normalized `candidate`.
 *
 * Both strings are normalized before comparison, so Unicode spoofing tricks
 * (Cyrillic, Greek, full-width) are neutralized first.
 *
 * @param {string} input      - The domain being tested (e.g. from a URL)
 * @param {string} candidate  - A known legitimate domain from the whitelist
 * @param {number} maxDistance - Maximum Levenshtein distance to call a match
 * @returns {boolean}
 */
export function isDomainLookalike(input, candidate, maxDistance = 2) {
  const normInput     = normalizeHomoglyphs(input);
  const normCandidate = normalizeHomoglyphs(candidate);
  return levenshtein(normInput, normCandidate) <= maxDistance;
}
