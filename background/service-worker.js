/**
 * background/service-worker.js
 * Canadian Scam Shield — MV3 service worker
 *
 * Responsibilities:
 *   • Load data files (whitelist.json, known-bad.json) with a simple in-memory cache
 *   • Run URL analysis on every tab navigation that reaches "complete"
 *   • Dispatch the appropriate UX response based on the verdict (badge / banner / full-page block)
 *   • Route messages from content scripts and the popup
 *
 * MV3 note: service workers are stateless between wake cycles.  The _cache object
 * below is intentionally scoped to this module — it persists for the lifetime of a
 * single worker activation and is rebuilt cheaply on the next wake if needed.
 */

import { analyzeUrl } from '../lib/url-analyzer.js';

// ---------------------------------------------------------------------------
// Data file cache
// ---------------------------------------------------------------------------

/**
 * In-memory cache keyed by filename.  Lives for the duration of one worker
 * activation; rebuilt automatically on the next wake if the worker was evicted.
 * @type {Object.<string, object>}
 */
const _cache = {};

/**
 * getDataFile(name)
 *
 * Fetches and JSON-parses a file from the extension's `data/` directory,
 * caching the result for subsequent calls within this activation lifetime.
 * Never throws — on any error it returns a safe empty fallback shape so that
 * analysis can proceed (with degraded accuracy) rather than crashing.
 *
 * @param {string} name  - Filename, e.g. 'whitelist.json' or 'known-bad.json'
 * @returns {Promise<object>}
 */
async function getDataFile(name) {
  if (_cache[name]) return _cache[name];

  try {
    const res = await fetch(chrome.runtime.getURL('data/' + name));
    _cache[name] = await res.json();
  } catch (e) {
    console.warn('CSS data load failed', name, e);
    // Return a structurally valid empty object that downstream code can handle
    // without null-checking — shape depends on which file failed.
    _cache[name] = name.includes('whitelist')
      ? { institutions: [] }
      : { domains: [] };
  }

  return _cache[name];
}

// ---------------------------------------------------------------------------
// Analysis helper
// ---------------------------------------------------------------------------

/**
 * runAnalysis(url)
 *
 * Loads both data files in parallel and delegates to the URL analyzer.
 * Returns the full result object from analyzeUrl().
 *
 * @param {string} url
 * @returns {Promise<{verdict:string, score:number, reasons:string[], officialUrl:string|null, institutionName:string|null}>}
 */
async function runAnalysis(url) {
  const [whitelist, knownBad] = await Promise.all([
    getDataFile('whitelist.json'),
    getDataFile('known-bad.json'),
  ]);
  return analyzeUrl(url, { whitelist, knownBad });
}

// ---------------------------------------------------------------------------
// Override allowlist
// ---------------------------------------------------------------------------
//
// When a user clicks "I understand the risk, continue anyway" on the warning
// page, we record that hostname so we do NOT re-block it for the rest of the
// browser session. Stored in chrome.storage.session (cleared when the browser
// closes) so an override never persists indefinitely.

/** Extract a lowercase hostname from a URL, or null if it can't be parsed. */
function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Returns true if the URL's hostname has been overridden this session. */
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

/** Record a session override for the URL's hostname. */
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

/** Navigate a tab to a safe page (New Tab page, falling back to about:blank). */
function goToSafety(tabId) {
  if (tabId == null) return;
  chrome.tabs.update(tabId, { url: 'chrome://newtab/' }).catch(() => {
    chrome.tabs.update(tabId, { url: 'about:blank' }).catch(() => {});
  });
}

// ---------------------------------------------------------------------------
// Lifecycle — onInstalled
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  console.log('Canadian Scam Shield installed');
});

// ---------------------------------------------------------------------------
// Navigation listener — tabs.onUpdated
// ---------------------------------------------------------------------------

/**
 * Fires when a tab's navigation status changes.  We only act when the page
 * has fully loaded (status === 'complete') and the URL is http(s) — browser
 * internal pages (chrome://, about:, etc.) are skipped.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only process fully loaded http(s) pages
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || !/^https?:\/\//i.test(tab.url)) return;

  // Respect a user's explicit "continue anyway" choice for this session —
  // otherwise we would immediately re-block the page they chose to visit.
  if (await isOverridden(tab.url)) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  try {
    const result = await runAnalysis(tab.url);
    const { verdict, score, reasons, officialUrl, institutionName } = result;

    if (verdict === 'high') {
      // Full-page block: redirect the tab to the warning page, passing all
      // context as URL query parameters so warning.js can render them.
      const params = new URLSearchParams({
        url: tab.url,
        score: String(score),
        // reasons is an array — JSON-encode then percent-encode for safe transport
        reasons: encodeURIComponent(JSON.stringify(reasons)),
        officialUrl: officialUrl ?? '',
        institutionName: institutionName ?? '',
        lang: 'en',
      });
      const warningUrl = chrome.runtime.getURL('warning/warning.html') + '?' + params.toString();
      chrome.tabs.update(tabId, { url: warningUrl });

    } else if (verdict === 'medium') {
      // Persistent banner: ask the content script to show an in-page warning.
      // Wrapped in try/catch because the content script may not be injected on
      // all frames (e.g. chrome-extension pages, PDF viewer, etc.).
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: 'SHOW_BANNER',
          level: 'medium',
          reasons,
          officialUrl,
          institutionName,
        });
      } catch (msgErr) {
        // Content script not present on this page — silently ignore.
        console.debug('CSS banner send failed (no content script?):', msgErr.message);
      }

    } else if (verdict === 'low') {
      // Subtle badge indicator on the extension icon for this tab
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#E8A317' });

    } else {
      // verdict === 'safe': clear any leftover badge from a previous navigation
      chrome.action.setBadgeText({ tabId, text: '' });
    }

  } catch (err) {
    // A single analysis failure must never crash the worker.
    console.error('CSS onUpdated analysis error:', err);
  }
});

// ---------------------------------------------------------------------------
// Message router — runtime.onMessage
// ---------------------------------------------------------------------------

/**
 * Handles messages from content scripts, the popup, and the warning page.
 *
 * Returns true from the listener when the response will be sent asynchronously
 * (i.e. for GET_STATUS), which keeps the message channel open.
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // ------------------------------------------------------------------
  // GET_STATUS — popup or content script asking for a URL's verdict
  // ------------------------------------------------------------------
  if (msg.type === 'GET_STATUS') {
    // Run the analysis asynchronously and reply when done.
    // We must return `true` synchronously to tell Chrome we'll call
    // sendResponse later; otherwise the channel is closed immediately.
    runAnalysis(msg.url)
      .then(result => sendResponse(result))
      .catch(err => {
        console.error('CSS GET_STATUS error:', err);
        sendResponse({ verdict: 'safe', score: 0, reasons: [], officialUrl: null, institutionName: null });
      });
    return true; // keep the message channel open for the async response
  }

  // ------------------------------------------------------------------
  // PAGE_LOAD — content script notifying that a page has loaded.
  // Navigation-triggered analysis is already handled by tabs.onUpdated,
  // so this is a no-op for now (reserved for future Layer 2 integration).
  // ------------------------------------------------------------------
  if (msg.type === 'PAGE_LOAD') {
    // Acknowledge the message; no action required at this stage.
    sendResponse({ ok: true });
    return false;
  }

  // ------------------------------------------------------------------
  // OVERRIDE_PROCEED — user clicked "continue anyway" on the warning page.
  // Record a session override for the hostname so we don't re-block it, then
  // acknowledge so the warning page can navigate. Replies asynchronously.
  // ------------------------------------------------------------------
  if (msg.type === 'OVERRIDE_PROCEED') {
    console.log('Override:', msg.url);
    addOverride(msg.url)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // keep the channel open for the async response
  }

  // ------------------------------------------------------------------
  // GO_BACK_SAFE — user clicked "go back to safety". Navigate the tab that
  // hosts the warning page to a safe page (cannot use history.back() because
  // the previous entry is the flagged page, which would re-block).
  // ------------------------------------------------------------------
  if (msg.type === 'GO_BACK_SAFE') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      goToSafety(tabId);
    } else {
      chrome.tabs
        .query({ active: true, currentWindow: true })
        .then(([active]) => active && goToSafety(active.id));
    }
    return false;
  }

  // ------------------------------------------------------------------
  // LOG_OVERRIDE — legacy/no-op diagnostic log (kept for compatibility).
  // ------------------------------------------------------------------
  if (msg.type === 'LOG_OVERRIDE') {
    console.log('Override (log only):', msg.url);
    return false;
  }

  // Unrecognised message type — no response needed
  return false;
});
