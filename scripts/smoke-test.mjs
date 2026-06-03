/**
 * scripts/smoke-test.mjs
 *
 * Runnable Node.js smoke test for lib/homoglyph.js, lib/url-analyzer.js,
 * and lib/content-analyzer.js.
 * No test framework required — run with:
 *   node scripts/smoke-test.mjs
 *
 * Exit code: 0 = all pass, 1 = one or more failures.
 */

import { normalizeHomoglyphs, levenshtein, isDomainLookalike } from '../lib/homoglyph.js';
import { analyzeUrl } from '../lib/url-analyzer.js';
import { analyzeContent } from '../lib/content-analyzer.js';

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
// analyzeContent tests
// ---------------------------------------------------------------------------

// Inline keywords fixture — small but representative, mirrors scam-keywords.json schema.
const keywords = {
  categories: {
    impersonation_terms: {
      weight: 15,
      cap: 45,
      terms: ['CRA', 'Canada Revenue Agency', 'GST/HST refund', 'tax refund'],
      terms_fr: [],
    },
    urgency_triggers: {
      weight: 20,
      cap: 40,
      terms: ['within 24 hours', 'final notice'],
      terms_fr: [],
    },
    payment_red_flags: {
      weight: 30,
      cap: 60,
      terms: ['gift card', 'Bitcoin'],
      terms_fr: [],
    },
    credential_harvesting: {
      weight: 25,
      structural: true,
      sin_terms: [
        'sin',
        'social insurance',
        'social insurance number',
        'nas',
        "numéro d'assurance sociale",
        'assurance sociale',
      ],
      cvv_terms: ['cvv', 'cvc', 'card verification', 'security code'],
      gov_suffixes: ['.gc.ca', '.canada.ca'],
    },
  },
};

// ── Case 1: CRA refund + gift card + "within 24 hours" on a scam portal ─────
// Expected: at least 'medium'; categoriesHit must include impersonation_terms
// and payment_red_flags.
// Scoring: impersonation = 15 (CRA) + 15 (tax refund) = 30
//          urgency = 20 (within 24 hours)
//          payment = 30 (gift card)
//          total = 80 → 'high'
{
  const result = analyzeContent(
    {
      title: 'CRA Refund Portal',
      metaDescription: '',
      text: 'You have a tax refund waiting. Purchase a gift card within 24 hours.',
      isHttps: true,
      url: 'https://refund-portal.example.com',
      fields: [],
    },
    { keywords, isPro: true },
  );

  // Verdict must be 'medium' or 'high'
  assert(
    "analyzeContent CRA+giftCard+24h → verdict 'medium' or 'high'",
    result.verdict === 'medium' || result.verdict === 'high',
    true,
  );
  assert(
    "analyzeContent CRA+giftCard+24h → categoriesHit includes 'impersonation_terms'",
    result.categoriesHit.includes('impersonation_terms'),
    true,
  );
  assert(
    "analyzeContent CRA+giftCard+24h → categoriesHit includes 'payment_red_flags'",
    result.categoriesHit.includes('payment_red_flags'),
    true,
  );
}

// ── Case 2: Benign marketing copy, no fields ──────────────────────────────────
// Expected: verdict 'safe', score 0, categoriesHit empty
{
  const result = analyzeContent(
    {
      title: 'Welcome to our store',
      metaDescription: 'Great deals every day',
      text: 'Buy our products today. Free shipping on orders over fifty dollars. No hidden fees.',
      isHttps: true,
      url: 'https://example.com',
      fields: [],
    },
    { keywords, isPro: true },
  );

  assert("analyzeContent benign → verdict 'safe'",    result.verdict,                'safe');
  assert('analyzeContent benign → score 0',           result.score,                  0);
  assert('analyzeContent benign → categoriesHit empty', result.categoriesHit.length, 0);
}

// ── Case 3: SIN field — Pro gate ─────────────────────────────────────────────
// The field has name:'sin' and labelText:'Social Insurance Number' on a non-gov host.
// With isPro:true  → credential weight added, reason mentions "Social Insurance".
// With isPro:false → nothing added.
{
  const sinField = { name: 'sin', type: 'text', labelText: 'Social Insurance Number' };
  const sinFeatures = {
    title: '',
    metaDescription: '',
    text: '',
    isHttps: true,
    url: 'https://refund-portal.example.com',
    fields: [sinField],
  };

  const proResult   = analyzeContent(sinFeatures, { keywords, isPro: true });
  const freeResult  = analyzeContent(sinFeatures, { keywords, isPro: false });

  // Pro: credential weight (25) must appear in the score
  assert(
    'analyzeContent SIN field, isPro:true → score includes credential weight (≥ 25)',
    proResult.score >= 25,
    true,
  );
  assert(
    "analyzeContent SIN field, isPro:true → reason mentions 'Social Insurance'",
    proResult.reasons.some(r => r.includes('Social Insurance')),
    true,
  );

  // Free: no SIN signal
  assert(
    'analyzeContent SIN field, isPro:false → score 0',
    freeResult.score,
    0,
  );
}

// ── Case 4: Substring guard — "crap" must not match "CRA"; "casino" must not match "sin"
// The text must produce verdict 'safe' with no categories fired.
{
  const result = analyzeContent(
    {
      title: '',
      metaDescription: '',
      text: 'the crap hit the fan, what a casino',
      isHttps: true,
      url: 'https://example.com',
      fields: [],
    },
    { keywords, isPro: true },
  );

  assert(
    "analyzeContent substring guard 'crap'/'casino' → verdict 'safe'",
    result.verdict,
    'safe',
  );
  assert(
    "analyzeContent substring guard → categoriesHit empty",
    result.categoriesHit.length,
    0,
  );
}

// ── Case 5: Password field — only fires when isHttps is false ────────────────
{
  const pwField = { type: 'password' };

  const httpResult  = analyzeContent(
    { title: '', metaDescription: '', text: '', isHttps: false, url: 'http://example.com',  fields: [pwField] },
    { keywords, isPro: true },
  );
  const httpsResult = analyzeContent(
    { title: '', metaDescription: '', text: '', isHttps: true,  url: 'https://example.com', fields: [pwField] },
    { keywords, isPro: true },
  );

  // Over HTTP: credential weight is added (score ≥ 25)
  assert(
    'analyzeContent password over HTTP (isHttps:false) → score includes credential weight (≥ 25)',
    httpResult.score >= 25,
    true,
  );
  assert(
    "analyzeContent password over HTTP → categoriesHit includes 'credential_harvesting'",
    httpResult.categoriesHit.includes('credential_harvesting'),
    true,
  );

  // Over HTTPS: no credential signal, score 0
  assert(
    'analyzeContent password over HTTPS (isHttps:true) → score 0',
    httpsResult.score,
    0,
  );
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`Results: ${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
