/**
 * lib/pro-checks.js — Shield Pro external threat checks.
 *
 * Two Pro-gated, network-backed enrichments used by the service worker AFTER
 * the local Layer 1/2 analysis, only when the user is Pro and the page is
 * borderline (so most navigations never hit the network):
 *
 *   • Domain age   — via RDAP (rdap.org), which is free and key-less. A very
 *                    new domain that also claims to be an institution is a
 *                    strong phishing signal. Cached 7 days.
 *   • PhishTank    — looks the URL up in PhishTank's database. Requires the
 *                    user's PhishTank app key (set in storage) and explicit
 *                    opt-in (the URL leaves the device). Cached 24 hours.
 *
 * All functions degrade gracefully: any network/parse failure returns null and
 * contributes nothing, so analysis never breaks or blocks on the network.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Cache helpers (chrome.storage.local)
// ---------------------------------------------------------------------------

async function cacheGet(key) {
  try {
    const obj = await chrome.storage.local.get(key);
    const entry = obj?.[key];
    if (entry && entry.expires > Date.now()) return entry.value;
  } catch { /* ignore */ }
  return undefined;
}

async function cacheSet(key, value, ttlMs) {
  try {
    await chrome.storage.local.set({ [key]: { value, expires: Date.now() + ttlMs } });
  } catch { /* ignore */ }
}

async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Domain age (RDAP)
// ---------------------------------------------------------------------------

/**
 * Returns the age of the registrable domain in days, or null if unknown.
 * Uses RDAP's "registration" event. Cached 7 days per host.
 *
 * @param {string} host
 * @returns {Promise<number|null>}
 */
export async function checkDomainAgeDays(host) {
  if (!host) return null;
  const cacheKey = 'rdap_' + host;
  const cached = await cacheGet(cacheKey);
  if (cached !== undefined) return cached;

  let ageDays = null;
  try {
    const res = await fetchWithTimeout('https://rdap.org/domain/' + encodeURIComponent(host));
    if (res.ok) {
      const data = await res.json();
      const reg = (data.events || []).find((e) => e.eventAction === 'registration');
      if (reg?.eventDate) {
        ageDays = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / DAY_MS);
      }
    }
  } catch { /* network/parse failure → null */ }

  await cacheSet(cacheKey, ageDays, 7 * DAY_MS);
  return ageDays;
}

// ---------------------------------------------------------------------------
// PhishTank
// ---------------------------------------------------------------------------

/**
 * Looks a URL up in PhishTank. Requires `appKey`. Cached 24h per URL.
 * Returns { inDatabase, verified, valid } or null on failure / no key.
 *
 * Privacy: this sends the URL to PhishTank — caller must ensure opt-in.
 *
 * @param {string} url
 * @param {string} appKey
 * @returns {Promise<{inDatabase:boolean, verified:boolean, valid:boolean}|null>}
 */
export async function checkPhishTank(url, appKey) {
  if (!url || !appKey) return null;
  const cacheKey = 'phishtank_' + url;
  const cached = await cacheGet(cacheKey);
  if (cached !== undefined) return cached;

  let result = null;
  try {
    const body = new URLSearchParams({ url, format: 'json', app_key: appKey });
    const res = await fetchWithTimeout('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (res.ok) {
      const data = await res.json();
      const r = data?.results;
      if (r) {
        result = {
          inDatabase: !!r.in_database,
          verified: !!r.verified,
          valid: !!r.valid,
        };
      }
    }
  } catch { /* failure → null */ }

  await cacheSet(cacheKey, result, DAY_MS);
  return result;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Runs the Pro checks and returns score/reason contributions plus an optional
 * hard escalation (confirmed PhishTank phish).
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {boolean} opts.hasInstitutionalClaim - whether local analysis saw an
 *        institution impersonation signal (gates the young-domain rule)
 * @param {boolean} [opts.phishtankOptIn]
 * @param {string}  [opts.phishtankKey]
 * @returns {Promise<{extraScore:number, reasons:string[], forceHigh:boolean}>}
 */
export async function runProChecks({ url, hasInstitutionalClaim, phishtankOptIn, phishtankKey }) {
  const out = { extraScore: 0, reasons: [], forceHigh: false };
  let host = null;
  try { host = new URL(url).hostname.toLowerCase().replace(/^www\./, ''); } catch { return out; }

  // Domain age (key-less, always allowed for Pro)
  const ageDays = await checkDomainAgeDays(host);
  if (ageDays !== null && ageDays < 90 && hasInstitutionalClaim) {
    out.extraScore += 30;
    out.reasons.push(
      `This domain was registered very recently (${ageDays} days ago) but claims to be an established organization.`
    );
  }

  // PhishTank (opt-in + key required; URL leaves the device)
  if (phishtankOptIn && phishtankKey) {
    const pt = await checkPhishTank(url, phishtankKey);
    if (pt && pt.inDatabase && pt.valid) {
      out.forceHigh = true;
      out.reasons.push('This exact address is listed as a confirmed phishing site in PhishTank.');
    }
  }

  return out;
}
