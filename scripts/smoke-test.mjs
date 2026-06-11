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

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { normalizeHomoglyphs, levenshtein, isDomainLookalike } from '../lib/homoglyph.js';
import { analyzeUrl } from '../lib/url-analyzer.js';
import { analyzeContent } from '../lib/content-analyzer.js';
import { analyzeMessage } from '../lib/message-analyzer.js';

const DATA_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
const loadData = (name) => JSON.parse(readFileSync(join(DATA_DIR, name), 'utf8'));

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
      terms_fr: ['Agence du revenu du Canada', 'remboursement d’impôt'],
    },
    urgency_triggers: {
      weight: 20,
      cap: 40,
      terms: ['within 24 hours', 'final notice'],
      terms_fr: ['dans les 24 heures'],
    },
    payment_red_flags: {
      weight: 30,
      cap: 60,
      terms: ['gift card', 'Bitcoin'],
      terms_fr: ['carte-cadeau'],
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

// ── Case 4b: a FRENCH-language scam page is detected regardless of UI language
{
  const frenchScam = analyzeContent(
    {
      title: 'Avis de l’Agence du revenu du Canada',
      text: 'Agence du revenu du Canada : votre remboursement d’impôt est prêt. '
          + 'Payez des frais avec une carte-cadeau dans les 24 heures.',
      isHttps: true,
      url: 'https://arc-remboursement.example.com',
      fields: [],
    },
    { keywords, lang: 'en' } // UI lang en, page is French — must still fire
  );
  assert(
    "analyzeContent(French scam page, UI=en) → 'medium'|'high'",
    ['medium', 'high'].includes(frenchScam.verdict),
    true
  );
  assert(
    'analyzeContent(French scam) → payment_red_flags hit',
    frenchScam.categoriesHit.includes('payment_red_flags'),
    true
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
// Layer 3 — message analyzer (uses the REAL bundled data files)
// ---------------------------------------------------------------------------

const realPatterns      = loadData('scam-sender-patterns.json');
const realSenderDomains = loadData('known-sender-domains.json');
const realWhitelist     = loadData('whitelist.json');
const msgOpts = {
  patterns: realPatterns,
  senderDomains: realSenderDomains,
  whitelist: realWhitelist,
};

const giftCardMsg = analyzeMessage(
  'Your payment is overdue. Purchase an iTunes gift card and send us the gift card code immediately.',
  msgOpts
);
assert(
  'analyzeMessage(gift card demand) → gift_card_payment_request fired',
  giftCardMsg.firedRules.some((r) => r.id === 'gift_card_payment_request'),
  true
);
assert('analyzeMessage(gift card demand) → score ≥ 55', giftCardMsg.score >= 55, true);

const craGmail = analyzeMessage(
  'Canada Revenue Agency: your tax refund of $458 is waiting. Click https://cra-refund.xyz/claim',
  { ...msgOpts, headers: { from: 'CRA Refund <refunds.cra@gmail.com>' } }
);
assert(
  'analyzeMessage(CRA from Gmail) → cra_free_provider fired',
  craGmail.firedRules.some((r) => r.id === 'cra_free_provider'),
  true
);
assert("analyzeMessage(CRA from Gmail) → verdict not 'safe'", craGmail.verdict !== 'safe', true);
assert(
  'analyzeMessage(CRA from Gmail) → officialContact phone is CRA line',
  craGmail.officialContact?.phone,
  '1-800-959-8281'
);
assert(
  'analyzeMessage(CRA from Gmail) → link extracted',
  craGmail.extractedLinks.includes('https://cra-refund.xyz/claim'),
  true
);
assert('analyzeMessage(CRA from Gmail) → senderDomain parsed', craGmail.senderDomain, 'gmail.com');

const imessage = analyzeMessage(
  'Your package cannot be delivered. Reply Y then exit the message and reopen the link.',
  msgOpts
);
assert(
  'analyzeMessage(iMessage Y trick) → imessage_evasion_reply_y fired',
  imessage.firedRules.some((r) => r.id === 'imessage_evasion_reply_y'),
  true
);

const sinMsg = analyzeMessage(
  'To verify your identity please provide your Social Insurance Number.',
  msgOpts
);
assert(
  'analyzeMessage(SIN request) → sin_request fired',
  sinMsg.firedRules.some((r) => r.id === 'sin_request'),
  true
);

const tollMsg = analyzeMessage(
  '407 ETR: You have an unpaid toll balance. Pay now at https://407-etr-pay.top/billing',
  msgOpts
);
assert(
  'analyzeMessage(407 toll smishing) → toll_road_unpaid_link fired',
  tollMsg.firedRules.some((r) => r.id === 'toll_road_unpaid_link'),
  true
);

const benignMsg = analyzeMessage("Hi mom, I'll be home for dinner at 6", msgOpts);
assert("analyzeMessage(benign text) → 'safe'", benignMsg.verdict, 'safe');
assert('analyzeMessage(benign text) → score < 30', benignMsg.score < 30, true);

const rcmpMsg = analyzeMessage(
  'This is the RCMP. A warrant has been issued for your arrest.',
  { ...msgOpts, headers: { from: 'RCMP <rcmp.canada@gmail.com>' } }
);
assert(
  'analyzeMessage(RCMP from Gmail) → police_free_provider fired',
  rcmpMsg.firedRules.some((r) => r.id === 'police_free_provider'),
  true
);

// ── Verified-sender dampening ────────────────────────────────────────────────
// Mail from a domain that suffix-matches the whitelist or an org's known
// sending domains must NOT be flagged by content-keyword rules (real Amazon
// emails mention gift cards; real Interac emails mention transfers).
const realAmazon = analyzeMessage(
  'Your package has shipped! Track at https://www.amazon.ca/track. '
  + 'You earned a $5 Amazon gift card reward.',
  { ...msgOpts, headers: { from: 'Amazon.ca <shipment-tracking@amazon.ca>' } }
);
assert("analyzeMessage(real amazon.ca sender) → 'safe'", realAmazon.verdict, 'safe');
assert('analyzeMessage(real amazon.ca) → senderVerified true', realAmazon.senderVerified, true);

const realInterac = analyzeMessage(
  'You received an INTERAC e-Transfer. We are processing your transfer.',
  { ...msgOpts, headers: { from: 'Interac <notify@payments.interac.ca>' } }
);
assert("analyzeMessage(real interac sender) → 'safe'", realInterac.verdict, 'safe');

// A whitelisted domain must never count as a lookalike of another whitelisted
// domain (amazon.ca is within edit distance 2 of amazon.com — both are real).
assert(
  'analyzeMessage(real amazon.ca) → no lookalike rule fired',
  realAmazon.firedRules.some((r) => r.id === 'domain_lookalike_high_value'),
  false
);

// Dampening must NOT protect lookalike or unverified senders…
const lookalikeAmazon = analyzeMessage(
  'You earned a $5 Amazon gift card reward. Send us the codes on the back.',
  { ...msgOpts, headers: { from: 'Amazon <deals@amaz0n.ca>' } }
);
assert(
  "analyzeMessage(amaz0n.ca lookalike) → still flagged",
  lookalikeAmazon.verdict !== 'safe',
  true
);

// …and structural danger from a "verified" sender must still flag.
const verifiedExe = analyzeMessage(
  'Invoice attached: statement.exe — open to view.',
  { ...msgOpts, headers: { from: 'Amazon <billing@amazon.ca>' } }
);
assert(
  'analyzeMessage(verified sender + .exe attachment) → executable_attachment fired',
  verifiedExe.firedRules.some((r) => r.id === 'executable_attachment'),
  true
);

// ── Sender-domain reputation (throwaway / machine-generated addresses) ──────
// Real scam samples that carry valid SPF/DKIM ("Trusted Sender") on nonsense
// domains, which no content keyword catches.
const repAntivirus = analyzeMessage(
  'LAST REMINDER: CONFIRMATION NEEDED. Your subscription may expire today.',
  { ...msgOpts, headers: { from: 'Total Protection <owrdcwrassu@fqwapijmo.again999.idood-esiot.me>' } }
);
assert(
  'analyzeMessage(throwaway domain) → flagged (medium/high)',
  ['medium', 'high'].includes(repAntivirus.verdict),
  true
);
assert(
  'analyzeMessage(throwaway domain) → random_sender_domain fired',
  repAntivirus.firedRules.some((r) => r.id === 'random_sender_domain'),
  true
);
assert(
  'analyzeMessage(throwaway domain) → random local part fired',
  repAntivirus.firedRules.some((r) => r.id === 'random_sender_local_part'),
  true
);

const repAbusedTld = analyzeMessage(
  'Payment Attempt Failed During Renewal of Your Cloud Storage Subscription.',
  { ...msgOpts, headers: { from: 'Cloud <ihwjsagmmaw@enoradnaj.briefing.perks.bany.biz.id>' } }
);
assert(
  'analyzeMessage(deep chain + abused TLD) → flagged',
  repAbusedTld.verdict !== 'safe',
  true
);

// Reputation must NOT fire on legitimate / verified / normal senders.
const repAmazon = analyzeMessage('Your order shipped.', {
  ...msgOpts, headers: { from: 'Amazon <shipment-tracking@amazon.ca>' },
});
assert(
  'analyzeMessage(verified sender) → no reputation rules',
  repAmazon.firedRules.some((r) => r.id.startsWith('random_sender') || r.id === 'deep_subdomain_chain_sender'),
  false
);
const repSmallBiz = analyzeMessage('Thanks for subscribing to our weekly recipes!', {
  ...msgOpts, headers: { from: 'Joe Cafe <newsletter@joescafe.com>' },
});
assert("analyzeMessage(normal small-biz sender) → 'safe'", repSmallBiz.verdict, 'safe');

// French explanations come from user_explanation_fr when lang='fr'
const sinFr = analyzeMessage(
  'To verify your identity please provide your Social Insurance Number.',
  { ...msgOpts, lang: 'fr' }
);
assert(
  'analyzeMessage(lang fr) → French explanation used',
  sinFr.firedRules[0]?.explanation.includes('assurance sociale'),
  true
);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`Results: ${passes} passed, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
