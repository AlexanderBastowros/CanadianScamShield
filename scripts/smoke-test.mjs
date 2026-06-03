/**
 * scripts/smoke-test.mjs
 *
 * Runnable Node.js smoke test for lib/homoglyph.js and lib/url-analyzer.js.
 * No test framework required — run with:
 *   node scripts/smoke-test.mjs
 *
 * Exit code: 0 = all pass, 1 = one or more failures.
 */

import { normalizeHomoglyphs, levenshtein, isDomainLookalike } from '../lib/homoglyph.js';
import { analyzeUrl } from '../lib/url-analyzer.js';

// ---------------------------------------------------------------------------
// Inline fixtures
// ---------------------------------------------------------------------------

const whitelist = {
  institutions: [
    {
      domain: 'canada.ca',
      name: 'Government of Canada',
      official_url: 'https://www.canada.ca',
      high_value: true,
    },
    {
      domain: 'cra-arc.gc.ca',
      name: 'Canada Revenue Agency',
      official_url: 'https://www.canada.ca/en/revenue-agency.html',
      high_value: true,
    },
    {
      domain: 'rbc.com',
      name: 'RBC Royal Bank',
      official_url: 'https://www.rbc.com',
      high_value: true,
    },
    {
      domain: 'gc.ca',
      name: 'Government of Canada',
      official_url: 'https://www.canada.ca',
      high_value: true,
    },
  ],
};

const knownBad = {
  domains: ['evil-scam-example.tk'],
};

// ---------------------------------------------------------------------------
// Tiny assert helper
// ---------------------------------------------------------------------------

let passes = 0;
let failures = 0;

function assert(description, actual, expected) {
  if (actual === expected) {
    console.log(`PASS: ${description}`);
    passes++;
  } else {
    console.log(`FAIL: ${description}`);
    console.log(`      expected: ${JSON.stringify(expected)}`);
    console.log(`      actual:   ${JSON.stringify(actual)}`);
    failures++;
  }
}

// ---------------------------------------------------------------------------
// homoglyph tests
// ---------------------------------------------------------------------------

// normalizeHomoglyphs — Cyrillic
// 'rЬc' contains Cyrillic SOFT SIGN (Ь → 'b' after lowercase 'ь' → 'b')
assert(
  "normalizeHomoglyphs('rЬc') → 'rbc'",
  normalizeHomoglyphs('rЬc'),
  'rbc'
);

// normalizeHomoglyphs — Greek omicron
assert(
  "normalizeHomoglyphs Greek ο → 'o'",
  normalizeHomoglyphs('ο'),
  'o'
);

// normalizeHomoglyphs — full-width 'Ａ' (U+FF21) → 'a'
assert(
  "normalizeHomoglyphs full-width 'Ａ' → 'a'",
  normalizeHomoglyphs('Ａ'),
  'a'
);

// ---------------------------------------------------------------------------
// levenshtein tests
// ---------------------------------------------------------------------------

assert("levenshtein('', 'abc') === 3",     levenshtein('', 'abc'),         3);
assert("levenshtein('kitten', 'sitting') === 3", levenshtein('kitten', 'sitting'), 3);

// ---------------------------------------------------------------------------
// isDomainLookalike tests
// ---------------------------------------------------------------------------

// 'rbc.com' vs 'rЬc.com' — Cyrillic b → after normalization 'rbc.com' vs 'rbc.com', distance 0
assert(
  "isDomainLookalike('rbc.com', 'rЬc.com') === true",
  isDomainLookalike('rbc.com', 'rЬc.com'),
  true
);

assert(
  "isDomainLookalike('rbc.com', 'google.com') === false",
  isDomainLookalike('rbc.com', 'google.com'),
  false
);

// ---------------------------------------------------------------------------
// analyzeUrl tests
// ---------------------------------------------------------------------------

// Exact whitelist match (www stripped → canada.ca)
assert(
  "analyzeUrl('https://www.canada.ca') → 'safe'",
  analyzeUrl('https://www.canada.ca', { whitelist, knownBad }).verdict,
  'safe'
);

// Subdomain of whitelisted multi-label domain (cra-arc.gc.ca suffix)
assert(
  "analyzeUrl('https://www.cra-arc.gc.ca/myaccount') → 'safe'",
  analyzeUrl('https://www.cra-arc.gc.ca/myaccount', { whitelist, knownBad }).verdict,
  'safe'
);

// CRA keyword + suspicious TLD → score ≥ 80 → 'high'
assert(
  "analyzeUrl('https://cra-refund-2026.xyz') → 'high'",
  analyzeUrl('https://cra-refund-2026.xyz', { whitelist, knownBad }).verdict,
  'high'
);

// Subdomain spoofing: cra.gc.ca embedded but registrable domain is refund-portal.xyz
assert(
  "analyzeUrl('https://cra.gc.ca.refund-portal.xyz') → 'high'",
  analyzeUrl('https://cra.gc.ca.refund-portal.xyz', { whitelist, knownBad }).verdict,
  'high'
);

// IP address → +40; also contains 'cra' → +50; total = 90 → 'high'
assert(
  "analyzeUrl('https://192.168.1.1/cra-login') → 'high'",
  analyzeUrl('https://192.168.1.1/cra-login', { whitelist, knownBad }).verdict,
  'high'
);

// Exact whitelist match (rbc.com)
assert(
  "analyzeUrl('https://rbc.com') → 'safe'",
  analyzeUrl('https://rbc.com', { whitelist, knownBad }).verdict,
  'safe'
);

// Cyrillic homoglyph of rbc.com → isDomainLookalike fires → +60 → 'medium'/'high'
// URL() will resolve 'rЬc.com' as-is since it is not valid IDN — we rely on
// homoglyph normalisation inside the analyzer.
assert(
  "analyzeUrl('https://rЬc.com') → 'high'",
  analyzeUrl('https://rЬc.com', { whitelist, knownBad }).verdict,
  'high'
);

// Known-bad domain
assert(
  "analyzeUrl('https://evil-scam-example.tk') → 'high'",
  analyzeUrl('https://evil-scam-example.tk', { whitelist, knownBad }).verdict,
  'high'
);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`Results: ${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
