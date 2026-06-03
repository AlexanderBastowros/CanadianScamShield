/**
 * lib/content-analyzer.js
 * Layer 2 page-content scam scorer for Canadian Scam Shield.
 *
 * Runs after the DOM is ready (via content-script.js), but this module itself
 * is a PURE ES module — no DOM, no Chrome APIs.  The caller is responsible for
 * extracting the `features` object from the page and passing it in.
 *
 * Exported function:
 *   analyzeContent(features, { keywords, isPro, lang })
 *     → { score, verdict, reasons, categoriesHit }
 *
 * Verdict bands (identical to url-analyzer.js):
 *   score ≥ 80 → 'high'
 *   score ≥ 55 → 'medium'
 *   score ≥ 30 → 'low'
 *   otherwise  → 'safe'
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * escapeRegex(str)
 *
 * Escapes all regex metacharacters in `str` and replaces one-or-more internal
 * whitespace characters with `\s+` so that "within 24 hours" still matches
 * "within  24 hours" (double space) etc.
 *
 * @param {string} str
 * @returns {string}
 */
function escapeRegex(str) {
  // Escape all metacharacters first …
  const escaped = str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // … then collapse any run of escaped-or-literal whitespace back to \s+
  // so multi-word terms match across inconsistent spacing.
  return escaped.replace(/\\ /g, '\\s+').replace(/\s+/g, '\\s+');
}

/**
 * buildTermRegex(term)
 *
 * Returns a case-insensitive RegExp that matches `term` at a word boundary
 * defined as: preceded by start-of-string or a non-alphanumeric character,
 * followed by end-of-string or a non-alphanumeric character.
 *
 * We deliberately avoid \b because it does not tolerate `/`, spaces, or
 * accented French characters as adjacent characters.
 *
 * @param {string} term
 * @returns {RegExp}
 */
function buildTermRegex(term) {
  return new RegExp(
    '(^|[^a-z0-9])' + escapeRegex(term.toLowerCase()) + '([^a-z0-9]|$)',
    'i'
  );
}

/**
 * matchesAnyTerm(haystack, terms)
 *
 * Returns the first term from `terms` that matches inside `haystack` using
 * word-boundary regex, or null if none match.  The haystack is expected to
 * already be lowercased by the caller.
 *
 * @param {string}   haystack - pre-lowercased text to search in
 * @param {string[]} terms    - list of terms to test
 * @returns {string|null}
 */
function matchesAnyTerm(haystack, terms) {
  for (const term of terms) {
    if (buildTermRegex(term).test(haystack)) {
      return term;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Known payment-processor domains whose CVV fields should not be flagged.
// Suffix-matched so that subdomains (e.g. js.stripe.com) are included.
// ---------------------------------------------------------------------------
const PAYMENT_PROCESSOR_ALLOWLIST = [
  'stripe.com',
  'paypal.com',
  'squareup.com',
  'square.com',
  'moneris.com',
  'interac.ca',
];

/**
 * hostEndsWith(host, suffix)
 *
 * Returns true if `host` equals `suffix` or ends with `'.' + suffix`.
 * This provides suffix-match logic for PAYMENT_PROCESSOR_ALLOWLIST.
 *
 * @param {string} host
 * @param {string} suffix
 * @returns {boolean}
 */
function hostEndsWith(host, suffix) {
  return host === suffix || host.endsWith('.' + suffix);
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * analyzeContent(features, options)
 *
 * Scores a page's extracted content for scam signals and returns a verdict.
 *
 * @param {object} features - Plain object extracted from the page (no DOM refs)
 * @param {string} [features.title]            - document.title
 * @param {string} [features.metaDescription]  - <meta name="description"> content
 * @param {string} [features.text]             - visible body text
 * @param {boolean} [features.isHttps]         - whether the page is served over HTTPS
 * @param {string}  [features.url]             - full page URL (used for host extraction)
 * @param {Array<{name?:string, id?:string, placeholder?:string, type?:string,
 *                autocomplete?:string, labelText?:string}>} [features.fields]
 *   - form field descriptors extracted by the content script
 *
 * @param {object}  [options]
 * @param {object}  [options.keywords]         - parsed scam-keywords.json object
 * @param {boolean} [options.isPro]            - enables Pro-gated signals (SIN detection)
 * @param {string}  [options.lang]             - 'en' or 'fr' (activates terms_fr array)
 * @param {boolean} [options.isPaymentDomain]  - SW-provided override: skip CVV flag
 *
 * @returns {{
 *   score:         number,
 *   verdict:       'safe'|'low'|'medium'|'high',
 *   reasons:       string[],
 *   categoriesHit: string[],
 * }}
 */
export function analyzeContent(
  features,
  {
    keywords      = { categories: {} },
    isPro         = true,
    lang          = 'en',
    isPaymentDomain = false,
  } = {}
) {
  const safeResult = { score: 0, verdict: 'safe', reasons: [], categoriesHit: [] };

  // Guard against missing or empty keywords data — return safe immediately.
  const categories = (keywords && keywords.categories) ? keywords.categories : {};

  // ── Step 1: Build the haystack ────────────────────────────────────────────
  // Concatenate title + meta description + body text, lowercased for matching.
  const title           = (features && features.title)           ? String(features.title)           : '';
  const metaDescription = (features && features.metaDescription) ? String(features.metaDescription) : '';
  const text            = (features && features.text)            ? String(features.text)            : '';
  const haystack        = (title + '\n' + metaDescription + '\n' + text).toLowerCase();

  const isHttps = features && features.isHttps === true;
  const fields  = (features && Array.isArray(features.fields)) ? features.fields : [];
  const rawUrl  = (features && features.url) ? String(features.url) : '';

  let score         = 0;
  const reasons     = [];
  const categoriesHit = [];

  // ── Step 2: Text-category scoring ────────────────────────────────────────
  // Iterate every category in keywords.categories that does NOT have
  // structural:true.  For each, collect all distinct terms (union of `terms`
  // and `terms_fr` when the active lang warrants it), test each against the
  // haystack with a word-boundary regex, accumulate weight per unique hit,
  // and apply the per-category cap.

  for (const [catKey, catDef] of Object.entries(categories)) {
    // Skip structural categories — handled separately below.
    if (catDef.structural) continue;

    const weight = typeof catDef.weight === 'number' ? catDef.weight : 0;
    const cap    = typeof catDef.cap    === 'number' ? catDef.cap    : Infinity;

    // Build the unified term list.  We always include `terms`; `terms_fr` is
    // added when the lang preference is French (future-proof for bilingual data).
    const termSet = new Set([
      ...(Array.isArray(catDef.terms)    ? catDef.terms    : []),
      ...(lang === 'fr' && Array.isArray(catDef.terms_fr) ? catDef.terms_fr : []),
    ]);

    if (termSet.size === 0) continue;

    let catScore = 0;
    let fired    = false;

    for (const term of termSet) {
      if (!term) continue;
      if (buildTermRegex(term).test(haystack)) {
        catScore += weight;
        fired = true;
        // Stop accumulating as soon as we hit the cap for this category.
        if (catScore >= cap) {
          catScore = cap;
          break;
        }
      }
    }

    if (fired) {
      score += catScore;
      categoriesHit.push(catKey);

      // Add one merged human-readable reason per category that fired.
      switch (catKey) {
        case 'impersonation_terms':
          reasons.push(
            'This page uses language scammers commonly use to impersonate Canadian organizations.'
          );
          break;
        case 'urgency_triggers':
          reasons.push(
            'This page creates false urgency or threats.'
          );
          break;
        case 'payment_red_flags':
          reasons.push(
            'This page demands payment by gift cards, crypto, or wire transfer.'
          );
          break;
        default:
          reasons.push(`Suspicious language detected (${catKey}).`);
      }
    }
  }

  // ── Step 3: Structural credential_harvesting ─────────────────────────────
  // These signals are based on form fields and URL/protocol properties rather
  // than keyword matching.  Each sub-check fires at most once.

  const credDef = categories['credential_harvesting'];
  const credWeight = credDef && typeof credDef.weight === 'number' ? credDef.weight : 25;

  // Derive the page hostname for gov-suffix and payment-processor checks.
  let pageHost = '';
  try {
    pageHost = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    // Malformed or missing URL — pageHost stays empty, gov/processor checks
    // will not match any suffix and therefore remain conservative (may fire).
  }

  const govSuffixes = (credDef && Array.isArray(credDef.gov_suffixes))
    ? credDef.gov_suffixes
    : ['.gc.ca', '.canada.ca'];

  let credentialHitFired = false; // tracks whether 'credential_harvesting' is in categoriesHit

  // ── 3a: SIN field (Pro-gated) ────────────────────────────────────────────
  // Fire when: isPro is true, the page host is NOT an official government
  // domain, AND at least one form field's descriptors contain a SIN-related
  // term.
  if (isPro) {
    const sinTerms = (credDef && Array.isArray(credDef.sin_terms)) ? credDef.sin_terms : [];
    const isGovHost = govSuffixes.some(sfx => pageHost.endsWith(sfx));

    if (!isGovHost && sinTerms.length > 0) {
      for (const field of fields) {
        const descriptors = [
          field.name        || '',
          field.id          || '',
          field.placeholder || '',
          field.labelText   || '',
        ].join(' ').toLowerCase();

        if (matchesAnyTerm(descriptors, sinTerms) !== null) {
          score += credWeight;
          reasons.push(
            'This page asks for your Social Insurance Number on a site that is not an' +
            ' official government (.gc.ca / .canada.ca) site.'
          );
          if (!credentialHitFired) {
            categoriesHit.push('credential_harvesting');
            credentialHitFired = true;
          }
          break; // fire at most once
        }
      }
    }
  }

  // ── 3b: Password over HTTP ───────────────────────────────────────────────
  // Fire when any field has type === 'password' and the page is not HTTPS.
  if (!isHttps) {
    for (const field of fields) {
      if ((field.type || '').toLowerCase() === 'password') {
        score += credWeight;
        reasons.push(
          'This page asks for a password over an insecure (non-HTTPS) connection.'
        );
        if (!credentialHitFired) {
          categoriesHit.push('credential_harvesting');
          credentialHitFired = true;
        }
        break; // fire at most once
      }
    }
  }

  // ── 3c: CVV field outside a known payment processor ──────────────────────
  // Fire when: isPaymentDomain is not true, the host is not in the processor
  // allowlist, and a field's descriptors match a CVV-related term (or the
  // autocomplete attribute is 'cc-csc').
  if (!isPaymentDomain) {
    const isProcessorHost = PAYMENT_PROCESSOR_ALLOWLIST.some(p => hostEndsWith(pageHost, p));

    if (!isProcessorHost) {
      const cvvTerms = (credDef && Array.isArray(credDef.cvv_terms)) ? credDef.cvv_terms : [];

      for (const field of fields) {
        const isAutocompleteCvv = (field.autocomplete || '').toLowerCase() === 'cc-csc';
        const descriptors = [
          field.name        || '',
          field.id          || '',
          field.placeholder || '',
          field.labelText   || '',
        ].join(' ').toLowerCase();
        const matchesCvvTerm = cvvTerms.length > 0
          ? matchesAnyTerm(descriptors, cvvTerms) !== null
          : false;

        if (isAutocompleteCvv || matchesCvvTerm) {
          score += credWeight;
          reasons.push(
            'This page asks for your card security code (CVV) outside a known payment provider.'
          );
          if (!credentialHitFired) {
            categoriesHit.push('credential_harvesting');
            credentialHitFired = true;
          }
          break; // fire at most once
        }
      }
    }
  }

  // ── Step 4: Cap + map verdict ─────────────────────────────────────────────
  // Identical band thresholds to url-analyzer.js.
  score = Math.min(100, score);

  let verdict;
  if      (score >= 80) verdict = 'high';
  else if (score >= 55) verdict = 'medium';
  else if (score >= 30) verdict = 'low';
  else                  verdict = 'safe';

  return { score, verdict, reasons, categoriesHit };
}
