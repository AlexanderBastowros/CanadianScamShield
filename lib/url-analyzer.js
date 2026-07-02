/**
 * lib/url-analyzer.js
 * Layer 1 URL detection for Canadian Scam Shield.
 *
 * Runs on every navigation (~5 ms target).  No DOM, no Chrome APIs —
 * compatible with Node.js and a Manifest V3 service worker.
 *
 * Exported function:
 *   analyzeUrl(url, { whitelist, knownBad })
 *     → { verdict, score, reasons, officialUrl, institutionName }
 */

import { normalizeHomoglyphs, isDomainLookalike } from './homoglyph.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** TLDs that are disproportionately abused by scammers. */
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.click', '.live', '.vip', '.online',
  '.site', '.info', '.biz', '.tk', '.ml', '.ga', '.cf', '.gq',
];

/**
 * Keywords found in hostnames that strongly imply a fake Government of Canada
 * domain — real GoC sites MUST end in .gc.ca or .canada.ca.
 */
const GOV_KEYWORDS = [
  'cra', 'canada-revenue', 'revenue-canada', 'arc-canada',
  'service-canada', 'servicecanada', 'ircc', 'rcmp', 'canada-post',
];

/** Legitimate GoC suffixes. */
const GOV_SUFFIXES = ['.gc.ca', '.canada.ca'];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Given a hostname, produce every possible "stripped-label" candidate by
 * progressively removing the leftmost label.
 *
 * e.g. "sub.cra-arc.gc.ca" → ["sub.cra-arc.gc.ca", "cra-arc.gc.ca", "gc.ca", "ca"]
 *
 * We include the original hostname as the first candidate so callers can test
 * both exact matches and suffix matches with a single loop.
 *
 * @param {string} hostname - lowercased hostname with www already stripped
 * @returns {string[]}
 */
function labelCandidates(hostname) {
  const candidates = [hostname];
  const parts = hostname.split('.');
  for (let i = 1; i < parts.length; i++) {
    candidates.push(parts.slice(i).join('.'));
  }
  return candidates;
}

/**
 * Count hyphens in the "registrable-domain label" portion of a hostname.
 * We strip the last two dot-separated segments (e.g. "gc.ca", "com") and
 * count hyphens in whatever remains.  If the hostname has only one or two
 * labels there is no label portion and we return 0.
 *
 * This is a pragmatic heuristic, not a strict eTLD+1 implementation.
 *
 * @param {string} hostname
 * @returns {number}
 */
function hyphenCountInLabels(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) {
    // e.g. "cra-refund.xyz" — the label IS the first part
    return (parts[0].match(/-/g) || []).length;
  }
  // For multi-label TLDs (gc.ca, canada.ca) we want everything except the
  // last two labels; for a plain TLD we want everything except the last one.
  // As a pragmatic proxy: count hyphens in everything except the last two
  // labels. Sum per label — a joined string would count separators as hyphens.
  return parts
    .slice(0, -2)
    .reduce((n, label) => n + (label.match(/-/g) || []).length, 0);
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * analyzeUrl(url, options)
 *
 * @param {string} url - The full URL to analyse (e.g. from a navigation event)
 * @param {object} options
 * @param {object} options.whitelist  - { institutions: Array<{domain, name, official_url, high_value}> }
 * @param {object} options.knownBad  - { domains: string[] }
 *
 * @returns {{
 *   verdict:         'safe'|'low'|'medium'|'high',
 *   score:           number,
 *   reasons:         string[],
 *   officialUrl:     string|null,
 *   institutionName: string|null,
 * }}
 */
export function analyzeUrl(url, {
  whitelist  = { institutions: [] },
  knownBad   = { domains: [] },
} = {}) {

  // ── Step 1: Parse URL ────────────────────────────────────────────────────

  // Extract the raw hostname from the URL string BEFORE passing to new URL().
  // This preserves original Unicode characters (e.g. Cyrillic, Greek) that the
  // WHATWG URL constructor converts to IDNA/punycode during host parsing.
  // We use this raw hostname for homoglyph detection (step 4a).
  const rawUrlStr = String(url);
  let rawHostname = ''; // will be populated below
  const rawHostMatch = rawUrlStr.match(/^https?:\/\/([^/?#:@[\]]+)/i);
  if (rawHostMatch) {
    let rh = rawHostMatch[1].toLowerCase();
    if (rh.startsWith('www.')) rh = rh.slice(4);
    rawHostname = rh;
  }

  // Quick scheme check on the raw string before constructing the URL object,
  // so we avoid throwing for obviously non-http(s) inputs.
  if (!/^https?:\/\//i.test(rawUrlStr)) {
    return { verdict: 'safe', score: 0, reasons: [], officialUrl: null, institutionName: null };
  }

  let parsed;
  let hostname;          // IDNA-normalised hostname, as returned by the URL constructor
  let idnaFailed = false; // true when the URL constructor rejected the hostname

  try {
    parsed = new URL(rawUrlStr);
    hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('www.')) {
      hostname = hostname.slice(4);
    }
  } catch {
    // The URL constructor failed (e.g. a mixed-script hostname like 'rьc.com' is
    // rejected by IDNA).  Fall back to the raw hostname extracted above so that
    // homoglyph analysis can still fire on the original Unicode characters.
    if (!rawHostname) {
      return { verdict: 'safe', score: 0, reasons: [], officialUrl: null, institutionName: null };
    }
    hostname = rawHostname;
    idnaFailed = true;
    // Create a minimal parsed-like object so later code referencing parsed.pathname
    // and parsed.protocol still works without null-checks everywhere.
    parsed = { hostname, pathname: '', protocol: 'https:' };
  }

  // Generate all stripped-label candidates for suffix matching
  const hostCandidates = labelCandidates(hostname);

  // ── Step 2: Whitelist exact / suffix match ───────────────────────────────
  // Build a Map from domain → institution for O(1) lookup
  const whitelistMap = new Map(
    (whitelist.institutions || []).map(inst => [inst.domain, inst])
  );

  for (const candidate of hostCandidates) {
    if (whitelistMap.has(candidate)) {
      const inst = whitelistMap.get(candidate);
      return {
        verdict: 'safe',
        score: 0,
        reasons: ['Verified Canadian institution'],
        officialUrl: inst.official_url ?? null,
        institutionName: inst.name ?? null,
      };
    }
  }

  // ── Step 3: Known-bad match ───────────────────────────────────────────────
  const knownBadSet = new Set(knownBad.domains || []);
  for (const candidate of hostCandidates) {
    if (knownBadSet.has(candidate)) {
      return {
        verdict: 'high',
        score: 100,
        reasons: ['Known scam/malicious domain'],
        officialUrl: null,
        institutionName: null,
      };
    }
  }

  // ── Steps 4+: Accumulate score ───────────────────────────────────────────
  let score = 0;
  const reasons = [];
  let officialUrl = null;
  let institutionName = null;

  // ── 4a: Homoglyph lookalike of a HIGH-VALUE entry ────────────────────────
  // We compare using rawHostname (pre-IDNA) so that Cyrillic/Greek lookalikes
  // that get encoded to punycode by the URL constructor are still caught here.
  const highValueEntries = (whitelist.institutions || []).filter(inst => inst.high_value === true);
  for (const entry of highValueEntries) {
    // Skip only if the raw hostname is byte-for-byte equal to the whitelisted
    // domain — genuine subdomains and Unicode imposters both proceed to the
    // distance check.  (True exact-domain matches are already caught in step 2.)
    if (rawHostname === entry.domain) continue;

    if (isDomainLookalike(rawHostname, entry.domain, 2)) {
      score += 60;
      reasons.push(`Looks like a fake version of ${entry.name} (${entry.domain})`);
      // First hit wins for officialUrl / institutionName
      if (officialUrl === null) {
        officialUrl = entry.official_url ?? null;
        institutionName = entry.name ?? null;
      }
      break; // One lookalike hit is enough
    }
  }

  // ── 4b: Fake government TLD enforcement ─────────────────────────────────
  // We check hostname + path together so that e.g. "192.168.1.1/cra-login"
  // correctly fires — the path can reveal the impersonation target even when
  // the hostname is a raw IP that contains no keywords.
  const urlForKeywordScan = (hostname + parsed.pathname).toLowerCase();
  const hasGovKeyword = GOV_KEYWORDS.some(kw => urlForKeywordScan.includes(kw));
  const hasGovSuffix  = GOV_SUFFIXES.some(sfx => hostname.endsWith(sfx));
  if (hasGovKeyword && !hasGovSuffix) {
    score += 50;
    reasons.push(
      'Fake government domain — real Government of Canada sites end in .gc.ca or .canada.ca'
    );
  }

  // ── 4c: Suspicious TLD ───────────────────────────────────────────────────
  if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
    score += 30;
    reasons.push('Uses a domain ending often abused by scammers');
  }

  // ── 4d: Excessive hyphens ────────────────────────────────────────────────
  if (hyphenCountInLabels(hostname) >= 3) {
    score += 20;
    reasons.push('Unusually many hyphens in the address');
  }

  // ── 4e: IP address in URL ────────────────────────────────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 40;
    reasons.push('Uses a raw IP address instead of a real domain name');
  }

  // ── 4f: Punycode or IDNA failure ─────────────────────────────────────────
  // Punycode (xn-- labels) is used to encode non-ASCII hostnames and is
  // frequently seen in Unicode-lookalike phishing domains.
  // An outright IDNA failure (mixed scripts, etc.) is an even stronger signal —
  // no legitimate site would use a hostname that IDNA processing rejects.
  if (hostname.includes('xn--')) {
    score += 40;
    reasons.push('Uses punycode (xn--), often used to disguise a fake address');
  } else if (idnaFailed) {
    // Hostname contained non-ASCII characters that were rejected by IDNA
    // processing — a hallmark of mixed-script homoglyph phishing.
    score += 40;
    reasons.push('Contains non-standard characters in the domain name (homoglyph attack)');
  }

  // ── 4g: Subdomain spoofing ───────────────────────────────────────────────
  // Fire if any whitelisted domain string appears as a dot-bounded substring
  // of the hostname BUT the hostname does NOT end with that whitelisted domain.
  // e.g. "cra.gc.ca.refund-portal.xyz" contains "cra.gc.ca" but ends with ".xyz"
  let subdomainSpoof = false;
  for (const wlDomain of whitelistMap.keys()) {
    // The whitelisted domain must appear inside the hostname somewhere that is
    // not at the very end (suffix match = legitimate subdomain, already caught
    // above). Dot-bound both ends so "canada.ca" cannot match mid-label inside
    // "canada.calgary-example.com".
    if (('.' + hostname).includes('.' + wlDomain + '.') && !hostname.endsWith(wlDomain)) {
      subdomainSpoof = true;
      break;
    }
  }
  if (subdomainSpoof) {
    score += 45;
    reasons.push(
      'Reads like a real site but the actual domain is different (subdomain spoofing)'
    );
  }

  // ── Step 5: Cap + map verdict ─────────────────────────────────────────────
  score = Math.min(score, 100);

  let verdict;
  if (score >= 80)      verdict = 'high';
  else if (score >= 55) verdict = 'medium';
  else if (score >= 30) verdict = 'low';
  else                  verdict = 'safe';

  return { verdict, score, reasons, officialUrl, institutionName };
}
