/**
 * lib/pro.js — Shield Pro license state for Canadian Scam Shield.
 *
 * Talks to the Cloudflare Worker backend (see server/worker.js) to verify
 * subscription licenses, and caches the result in chrome.storage.sync.
 *
 * Pure-ish ES module: tolerant of a missing chrome global so it can be imported
 * in Node (verification then degrades to a no-op / network_error).
 *
 * Storage keys (chrome.storage.sync):
 *   proLicense    — the CSS-XXXX-XXXX-XXXX-XXXX key the user activated
 *   proStatus     — 'active' | 'inactive' | 'none'
 *   proCheckedAt  — ISO timestamp of the last successful verify
 */

/** Single source of truth for the backend URL. Replace after deploying. */
export const PRO_API_BASE = 'https://canadian-scam-shield-pro.YOUR-SUBDOMAIN.workers.dev';

/** fetch with an AbortController timeout (default 10s). */
async function fetchWithTimeout(url, ms = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function hasStorage() {
  return typeof chrome !== 'undefined' && chrome.storage?.sync;
}

/**
 * Reads the cached Pro state.
 * @returns {Promise<{isPro:boolean, license:string|null, status:string, checkedAt:string|null}>}
 */
export async function getProState() {
  if (!hasStorage()) {
    return { isPro: false, license: null, status: 'none', checkedAt: null };
  }
  try {
    const { proLicense = null, proStatus = 'none', proCheckedAt = null } =
      await chrome.storage.sync.get(['proLicense', 'proStatus', 'proCheckedAt']);
    return {
      isPro: proStatus === 'active',
      license: proLicense,
      status: proStatus,
      checkedAt: proCheckedAt,
    };
  } catch {
    return { isPro: false, license: null, status: 'none', checkedAt: null };
  }
}

/**
 * Verifies a license key against the backend and caches the result.
 *
 * On a network/timeout failure we return { valid:null, status:'network_error' }
 * and DO NOT overwrite the stored state — the user keeps their last known
 * status (grace period), so an offline moment never silently downgrades them.
 *
 * @param {string} key
 * @returns {Promise<{valid:boolean|null, status:string, plan?:string}>}
 */
export async function verifyLicense(key) {
  const cleaned = String(key || '').trim().toUpperCase();
  if (!cleaned) return { valid: false, status: 'unknown' };

  try {
    const res = await fetchWithTimeout(
      `${PRO_API_BASE}/verify?key=${encodeURIComponent(cleaned)}`
    );
    const body = await res.json();
    if (hasStorage()) {
      await chrome.storage.sync.set({
        proLicense: cleaned,
        proStatus: body.valid ? 'active' : 'inactive',
        proCheckedAt: new Date().toISOString(),
      });
    }
    return body;
  } catch {
    // Network/timeout — preserve existing cached state.
    return { valid: null, status: 'network_error' };
  }
}

/**
 * Re-verifies the stored license if it hasn't been checked within maxAgeHours.
 * Called from a daily alarm in the service worker.
 *
 * @param {number} [maxAgeHours=24]
 */
export async function refreshLicenseIfStale(maxAgeHours = 24) {
  if (!hasStorage()) return;
  const { license, checkedAt } = await getProState();
  if (!license) return;
  const ageMs = checkedAt ? Date.now() - new Date(checkedAt).getTime() : Infinity;
  if (ageMs >= maxAgeHours * 3600 * 1000) {
    await verifyLicense(license);
  }
}
