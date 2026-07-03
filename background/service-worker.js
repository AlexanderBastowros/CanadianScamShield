/**
 * background/service-worker.js
 * Canadian Scam Shield — MV3 service worker
 *
 * Responsibilities:
 *   • Load data files (whitelist, known-bad, keywords, patterns, sender-domains)
 *     with a layered cache: memory → chrome.storage.local (live updates) →
 *     bundled package → safe fallback.
 *   • Run Layer 1 (URL) analysis on every navigation, combine with Layer 2
 *     (page content) signals, apply the user's sensitivity setting and custom
 *     allow/block lists, and dispatch badge / banner / full-page warning.
 *   • Serve Layer 3 (CHECK_MESSAGE) requests from the popup's message checker.
 *   • Keep threat data fresh via a daily alarm, and refresh the Pro license.
 *
 * MV3 note: service workers are stateless between wake cycles.  The _cache object
 * is scoped to one activation and rebuilt cheaply on the next wake.
 */

import { analyzeUrl }      from '../lib/url-analyzer.js';
import { analyzeContent }  from '../lib/content-analyzer.js';
import { analyzeMessage }  from '../lib/message-analyzer.js';
import { getProState, refreshLicenseIfStale } from '../lib/pro.js';
import { runProChecks } from '../lib/pro-checks.js';
import { t } from '../lib/i18n.js';

// Public GitHub raw base for live data updates (master branch of this repo).
const DATA_BASE_URL =
  'https://raw.githubusercontent.com/AlexanderBastowros/CanadianScamShield/master/data/';

const DATA_FILES = [
  'whitelist.json',
  'scam-sender-patterns.json',
  'known-sender-domains.json',
  'known-bad.json',
  'scam-keywords.json',
];

// ---------------------------------------------------------------------------
// Data file cache (layered)
// ---------------------------------------------------------------------------

const _cache = {};

/** The empty-but-valid fallback shape for a given data filename. */
function fallbackShape(name) {
  if (name.includes('whitelist')) return { institutions: [] };
  if (name.includes('keyword')) return { categories: {} };
  if (name.includes('pattern')) return { rules: [] };
  if (name.includes('sender-domains')) return { organizations: [] };
  return { domains: [] };
}

/**
 * getDataFile(name)
 *
 * Resolution order:
 *   1. in-memory _cache
 *   2. chrome.storage.local 'data_<name>' (written by the daily updater)
 *   3. bundled file fetched from the package
 *   4. safe empty fallback
 * The winner is cached in memory. Never throws.
 */
async function getDataFile(name) {
  if (_cache[name]) return _cache[name];

  // 2. Live-updated copy in local storage
  try {
    const stored = await chrome.storage.local.get('data_' + name);
    if (stored && stored['data_' + name]) {
      _cache[name] = stored['data_' + name];
      return _cache[name];
    }
  } catch {
    /* fall through to bundled */
  }

  // 3. Bundled package file
  try {
    const res = await fetch(chrome.runtime.getURL('data/' + name));
    _cache[name] = await res.json();
  } catch (e) {
    console.warn('CSS data load failed', name, e);
    _cache[name] = fallbackShape(name);
  }
  return _cache[name];
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/** Reads user settings with sensible defaults. */
async function getSettings() {
  try {
    return await chrome.storage.sync.get({
      language: 'en',
      sensitivity: 'balanced',
      customWhitelist: [],
      customBlocklist: [],
      phishtankOptIn: false,
    });
  } catch {
    return {
      language: 'en', sensitivity: 'balanced',
      customWhitelist: [], customBlocklist: [], phishtankOptIn: false,
    };
  }
}

/**
 * applySensitivity(score, sensitivity)
 *   strict     → +15 (warn more)
 *   permissive → -15 (warn less)
 *   balanced   → unchanged
 * Result clamped to 0..100.
 */
function applySensitivity(score, sensitivity) {
  const shift = sensitivity === 'strict' ? 15 : sensitivity === 'permissive' ? -15 : 0;
  return Math.max(0, Math.min(100, score + shift));
}

// ---------------------------------------------------------------------------
// Verdict helpers
// ---------------------------------------------------------------------------

function bandOf(score) {
  return score >= 80 ? 'high'
       : score >= 55 ? 'medium'
       : score >= 30 ? 'low'
       :               'safe';
}

const VERDICT_RANK = { safe: 0, low: 1, medium: 2, high: 3 };

/** Suffix match: host equals entry or ends with '.'+entry. */
function hostMatchesList(host, list) {
  if (!host || !Array.isArray(list)) return false;
  return list.some((entry) => {
    const e = String(entry).toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
    return host === e || host.endsWith('.' + e);
  });
}

function buildWarningUrl(url, score, reasons, officialUrl, institutionName, lang) {
  const params = new URLSearchParams({
    url,
    score: String(score),
    reasons: encodeURIComponent(JSON.stringify(reasons)),
    officialUrl:     officialUrl     ?? '',
    institutionName: institutionName ?? '',
    lang,
  });
  return chrome.runtime.getURL('warning/warning.html') + '?' + params.toString();
}

// ---------------------------------------------------------------------------
// Layer 1 analysis (with custom allow/block lists)
// ---------------------------------------------------------------------------

/**
 * runAnalysis(url) — custom lists first, then the URL analyzer.
 * Custom lists are checked before analyzeUrl so the user's choices always win.
 */
async function runAnalysis(url) {
  const host = hostnameOf(url);
  const settings = await getSettings();

  if (host && hostMatchesList(host, settings.customWhitelist)) {
    return { verdict: 'safe', score: 0, reasons: ['Trusted by you'], officialUrl: null, institutionName: null };
  }
  if (host && hostMatchesList(host, settings.customBlocklist)) {
    return { verdict: 'high', score: 100, reasons: ['Blocked by your settings'], officialUrl: null, institutionName: null };
  }

  const [whitelist, knownBad] = await Promise.all([
    getDataFile('whitelist.json'),
    getDataFile('known-bad.json'),
  ]);
  return analyzeUrl(url, { whitelist, knownBad });
}

// ---------------------------------------------------------------------------
// Override allowlist (session-scoped)
// ---------------------------------------------------------------------------

function hostnameOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

async function isOverridden(url) {
  const host = hostnameOf(url);
  if (!host) return false;
  try {
    const { _overrides = {} } = await chrome.storage.session.get('_overrides');
    return _overrides[host] === true;
  } catch {
    return false;
  }
}

async function addOverride(url) {
  const host = hostnameOf(url);
  if (!host) return;
  try {
    const { _overrides = {} } = await chrome.storage.session.get('_overrides');
    _overrides[host] = true;
    await chrome.storage.session.set({ _overrides });
  } catch (e) {
    console.warn('CSS could not persist override:', e);
  }
}

function goToSafety(tabId) {
  if (tabId == null) return;
  chrome.tabs.update(tabId, { url: 'chrome://newtab/' }).catch(() => {
    chrome.tabs.update(tabId, { url: 'about:blank' }).catch(() => {});
  });
}

// ---------------------------------------------------------------------------
// Daily data update
// ---------------------------------------------------------------------------

/** fetch JSON with a timeout. Returns parsed object or throws. */
async function fetchJson(url, ms = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Pulls each data file from GitHub raw, and if its `version` differs from the
 * currently loaded copy, stores it in chrome.storage.local and refreshes the
 * in-memory cache. Any per-file failure is logged and skipped — existing data
 * is never cleared (fail closed / never fail open).
 *
 * @returns {Promise<string>} the new dataLastUpdated ISO timestamp
 */
async function fetchDataUpdates() {
  for (const file of DATA_FILES) {
    try {
      const remote = await fetchJson(DATA_BASE_URL + file);
      const current = await getDataFile(file);
      const remoteVer = remote?.version ?? null;
      const currentVer = current?.version ?? null;
      if (remoteVer && remoteVer !== currentVer) {
        await chrome.storage.local.set({ ['data_' + file]: remote });
        _cache[file] = remote;
        console.log('CSS data updated:', file, currentVer, '→', remoteVer);
      }
    } catch (e) {
      console.warn('CSS data update skipped for', file, e.message);
    }
  }
  const dataLastUpdated = new Date().toISOString();
  try { await chrome.storage.local.set({ dataLastUpdated }); } catch { /* ignore */ }
  return dataLastUpdated;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

const REPO_SLUG = 'AlexanderBastowros/CanadianScamShield';

chrome.runtime.onInstalled.addListener((details) => {
  console.log('Canadian Scam Shield installed');
  chrome.alarms.create('dailyDataUpdate', { periodInMinutes: 1440 });
  chrome.alarms.create('licenseRefresh', { periodInMinutes: 1440 });

  // Show the onboarding page on first install (not on updates).
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') });
  }
});

/**
 * Builds a prefilled GitHub "false positive" issue URL. Only the information the
 * user is already looking at is included (the flagged URL/sender, the verdict,
 * and the reasons) — no browsing history or personal data.
 */
function buildFalsePositiveIssueUrl({ kind, reportedUrl, sender, verdict, reasons }) {
  const version = chrome.runtime.getManifest().version;
  const title = kind === 'message'
    ? 'False positive: legitimate message flagged'
    : 'False positive: legitimate site flagged';
  const lines = [
    'Canadian Scam Shield flagged something that looks legitimate.',
    '',
    `- Type: ${kind === 'message' ? 'email/text message' : 'website'}`,
    reportedUrl ? `- Address: ${reportedUrl}` : null,
    sender ? `- Sender: ${sender}` : null,
    verdict ? `- Verdict shown: ${verdict}` : null,
    Array.isArray(reasons) && reasons.length ? `- Reasons shown:\n${reasons.map((r) => `  - ${r}`).join('\n')}` : null,
    `- Extension version: ${version}`,
    '',
    'Why I think this is legitimate (please add detail):',
    '',
  ].filter(Boolean);
  const params = new URLSearchParams({
    title,
    labels: 'false-positive',
    body: lines.join('\n'),
  });
  return `https://github.com/${REPO_SLUG}/issues/new?${params.toString()}`;
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'dailyDataUpdate') {
    fetchDataUpdates().catch((e) => console.warn('CSS dailyDataUpdate failed', e));
  } else if (alarm.name === 'licenseRefresh') {
    refreshLicenseIfStale().catch((e) => console.warn('CSS licenseRefresh failed', e));
  }
});

// ---------------------------------------------------------------------------
// Navigation listener — tabs.onUpdated (Layer 1)
// ---------------------------------------------------------------------------

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || !/^https?:\/\//i.test(tab.url)) return;

  if (await isOverridden(tab.url)) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  try {
    const settings = await getSettings();
    const result = await runAnalysis(tab.url);
    const { reasons, officialUrl, institutionName } = result;

    // Apply sensitivity, then re-band. The raw-verdict floor is skipped for
    // 'permissive' — otherwise it would cancel the -15 downgrade and make the
    // setting a no-op (for strict/balanced the floor is a defensive no-op).
    const adjusted = applySensitivity(result.score, settings.sensitivity);
    let verdict = bandOf(adjusted);
    if (settings.sensitivity !== 'permissive' &&
        VERDICT_RANK[result.verdict] > VERDICT_RANK[verdict]) verdict = result.verdict;

    if (verdict === 'high') {
      chrome.tabs.update(tabId, {
        url: buildWarningUrl(tab.url, adjusted, reasons, officialUrl, institutionName, settings.language),
      });
    } else if (verdict === 'medium') {
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: 'SHOW_BANNER', level: 'medium', reasons, officialUrl, institutionName,
        });
      } catch (msgErr) {
        console.debug('CSS banner send failed (no content script?):', msgErr.message);
      }
    } else if (verdict === 'low') {
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#E8A317' });
    } else {
      chrome.action.setBadgeText({ tabId, text: '' });
    }
  } catch (err) {
    console.error('CSS onUpdated analysis error:', err);
  }
});

// ---------------------------------------------------------------------------
// Message router — runtime.onMessage
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // GET_STATUS — popup asking for the active tab's verdict
  if (msg.type === 'GET_STATUS') {
    runAnalysis(msg.url)
      .then((result) => sendResponse(result))
      .catch((err) => {
        console.error('CSS GET_STATUS error:', err);
        sendResponse({ verdict: 'safe', score: 0, reasons: [], officialUrl: null, institutionName: null });
      });
    return true;
  }

  // PAGE_LOAD — content-script ack (navigation handled by tabs.onUpdated)
  if (msg.type === 'PAGE_LOAD') {
    sendResponse({ ok: true });
    return false;
  }

  // PAGE_FEATURES — Layer 2 page-content signals; combine with Layer 1
  if (msg.type === 'PAGE_FEATURES') {
    (async () => {
      try {
        const url = msg.url;
        const tabId = sender.tab?.id;
        if (tabId == null) return;
        if (await isOverridden(url)) return;

        const settings = await getSettings();
        const l1 = await runAnalysis(url);
        if (l1.verdict === 'safe' && l1.institutionName) return; // verified institution

        const keywords = await getDataFile('scam-keywords.json');
        // SIN-field detection ships free for now → isPro:true regardless of license.
        const l2 = analyzeContent(msg.features, { keywords, isPro: true });

        let combinedRaw = Math.min(100, l1.score + l2.score);

        const seen = new Set(l1.reasons);
        const mergedReasons = [...l1.reasons];
        for (const r of l2.reasons) if (!seen.has(r)) { seen.add(r); mergedReasons.push(r); }

        // [Pro] Borderline pages get external enrichment (domain age, PhishTank).
        // Gated to low/medium so most navigations never touch the network.
        const proState = await getProState();
        if (proState.isPro && combinedRaw >= 30 && combinedRaw < 80) {
          const hasInstitutionalClaim =
            l2.categoriesHit?.includes('impersonation_terms') || !!l1.institutionName;
          const { phishtankOptIn, phishtankKey } = await chrome.storage.sync.get({
            phishtankOptIn: false, phishtankKey: '',
          });
          const pro = await runProChecks({
            url, hasInstitutionalClaim, phishtankOptIn, phishtankKey,
          });
          combinedRaw = Math.min(100, combinedRaw + pro.extraScore);
          for (const r of pro.reasons) if (!seen.has(r)) { seen.add(r); mergedReasons.push(r); }
          if (pro.forceHigh) combinedRaw = 100;
        }

        const combined = applySensitivity(combinedRaw, settings.sensitivity);

        // Same permissive exception as the navigation path above.
        let finalVerdict = bandOf(combined);
        if (settings.sensitivity !== 'permissive' &&
            VERDICT_RANK[l1.verdict] > VERDICT_RANK[finalVerdict]) finalVerdict = l1.verdict;

        if (finalVerdict === 'high') {
          chrome.tabs.update(tabId, {
            url: buildWarningUrl(url, combined, mergedReasons, l1.officialUrl ?? '', l1.institutionName ?? '', settings.language),
          });
        } else if (finalVerdict === 'medium') {
          try {
            await chrome.tabs.sendMessage(tabId, {
              type: 'SHOW_BANNER', level: 'medium', reasons: mergedReasons,
              officialUrl: l1.officialUrl, institutionName: l1.institutionName,
            });
          } catch (msgErr) {
            console.debug('CSS banner send failed (no content script?):', msgErr.message);
          }
        } else if (finalVerdict === 'low') {
          chrome.action.setBadgeText({ tabId, text: '!' });
          chrome.action.setBadgeBackgroundColor({ tabId, color: '#E8A317' });
        }
      } catch (err) {
        console.error('CSS PAGE_FEATURES analysis error:', err);
      }
    })();
    return false;
  }

  // CHECK_MESSAGE — Layer 3 email/SMS paste checker (from popup)
  if (msg.type === 'CHECK_MESSAGE') {
    (async () => {
      try {
        const [patterns, senderDomains, whitelist, settings, proState] = await Promise.all([
          getDataFile('scam-sender-patterns.json'),
          getDataFile('known-sender-domains.json'),
          getDataFile('whitelist.json'),
          getSettings(),
          getProState(),
        ]);
        const headers = (msg.sender || msg.subject)
          ? { from: msg.sender || null, subject: msg.subject || '' }
          : null;
        const result = analyzeMessage(msg.rawText || '', {
          patterns, senderDomains, whitelist, headers,
          isPro: proState.isPro, lang: settings.language,
        });
        sendResponse(result);
      } catch (err) {
        console.error('CSS CHECK_MESSAGE error:', err);
        sendResponse({ score: 0, verdict: 'safe', firedRules: [], extractedLinks: [], senderDomain: null, officialContact: null });
      }
    })();
    return true;
  }

  // REPORT_FALSE_POSITIVE — open a prefilled GitHub issue in a new tab.
  // Sent from the warning page, the in-page banner, the mail chip, or the popup.
  if (msg.type === 'REPORT_FALSE_POSITIVE') {
    try {
      const url = buildFalsePositiveIssueUrl({
        kind: msg.kind || 'site',
        reportedUrl: msg.reportedUrl || null,
        sender: msg.sender || null,
        verdict: msg.verdict || null,
        reasons: msg.reasons || [],
      });
      chrome.tabs.create({ url });
      sendResponse({ ok: true });
    } catch (e) {
      console.error('CSS REPORT_FALSE_POSITIVE error:', e);
      sendResponse({ ok: false });
    }
    return true;
  }

  // GET_I18N — content scripts (which can't import lib/i18n.js) request
  // localized UI strings for the user's current language.
  if (msg.type === 'GET_I18N') {
    (async () => {
      const { language } = await getSettings();
      const out = {};
      for (const k of (msg.keys || [])) out[k] = t(k, language);
      sendResponse({ lang: language, strings: out });
    })();
    return true;
  }

  // UPDATE_DATA_NOW — options "Update now" button
  if (msg.type === 'UPDATE_DATA_NOW') {
    fetchDataUpdates()
      .then((dataLastUpdated) => sendResponse({ ok: true, dataLastUpdated }))
      .catch((err) => { console.error('CSS UPDATE_DATA_NOW error:', err); sendResponse({ ok: false }); });
    return true;
  }

  // OVERRIDE_PROCEED — "continue anyway" on the warning page
  if (msg.type === 'OVERRIDE_PROCEED') {
    addOverride(msg.url)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  // GO_BACK_SAFE — "go back to safety" on the warning page
  if (msg.type === 'GO_BACK_SAFE') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      goToSafety(tabId);
    } else {
      chrome.tabs.query({ active: true, currentWindow: true })
        .then(([active]) => active && goToSafety(active.id));
    }
    return false;
  }

  // LOG_OVERRIDE — legacy/no-op diagnostic log
  if (msg.type === 'LOG_OVERRIDE') {
    console.log('Override (log only):', msg.url);
    return false;
  }

  return false;
});
