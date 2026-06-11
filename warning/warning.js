/**
 * warning/warning.js — Full-page scam warning screen
 *
 * Receives data from the service worker via URL query parameters:
 *   url            — the suspicious URL (single-encoded by URLSearchParams)
 *   score          — numeric risk score (string)
 *   reasons        — encodeURIComponent(JSON.stringify(string[])) placed into URLSearchParams
 *                    → effectively double-encoded; decode with JSON.parse(decodeURIComponent(raw))
 *   officialUrl    — the real institution URL (may be empty string)
 *   institutionName — the institution name (may be empty string)
 *   lang           — 'en' or 'fr' (defaults to 'en')
 *
 * SECURITY NOTE:
 *   `url`, `institutionName`, and every entry in `reasons` come from an untrusted
 *   navigated website and must NEVER be assigned to innerHTML / insertAdjacentHTML.
 *   Always set via textContent or setAttribute('title', …).
 */

import { t } from '../lib/i18n.js';

// ---------------------------------------------------------------------------
// Parse URL query parameters
// ---------------------------------------------------------------------------

const params     = new URLSearchParams(location.search);
const lang       = params.get('lang') || 'en';

// Untrusted strings — NEVER used with innerHTML
const url            = params.get('url')            ?? '';
const institutionName = params.get('institutionName') ?? '';
const officialUrl    = params.get('officialUrl')    ?? '';
const score          = params.get('score')          ?? '';

// reasons is double-encoded: URLSearchParams already decoded once, we decode the inner layer
const rawReasons = params.get('reasons');
let reasons = [];
try {
  reasons = rawReasons ? JSON.parse(decodeURIComponent(rawReasons)) : [];
} catch {
  reasons = [];
}

// ---------------------------------------------------------------------------
// Helper: set text content safely
// ---------------------------------------------------------------------------

/**
 * Sets textContent on an element found by id.
 * No-ops if element not found.
 * @param {string} id
 * @param {string} text
 */
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ---------------------------------------------------------------------------
// Populate the page
// ---------------------------------------------------------------------------

// <title>
document.title = t('warning_title', lang);

// Update the <html lang> attribute so screen readers announce in the correct language
document.documentElement.lang = lang;

// App name in header
setText('app-name', t('app_name', lang));

// Heading & subheading
setText('warning-heading', t('warning_heading', lang));
setText('warning-subheading', t('warning_subheading', lang));

// Suspicious URL label
setText('url-label', t('warning_url_label', lang));

// Suspicious URL value — truncated visually via CSS but full value in title attribute
const urlEl = document.getElementById('suspicious-url');
if (urlEl) {
  urlEl.textContent = url;
  urlEl.setAttribute('title', url);
}

// "Why we flagged this" heading
setText('reasons-heading', t('warning_why_flagged', lang));

// Reasons list — each item is untrusted; use textContent only
const reasonsList = document.getElementById('reasons-list');
if (reasonsList) {
  if (reasons.length > 0) {
    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;              // untrusted — textContent only
      reasonsList.appendChild(li);
    });
  } else {
    // Graceful fallback: hide the section if no reasons were provided
    const reasonsSection = reasonsList.closest('.reasons-section');
    if (reasonsSection) reasonsSection.hidden = true;
  }
}

// Real-site block
const realSiteSection = document.getElementById('real-site-section');
const realSiteLabel   = document.getElementById('real-site-label');

if (realSiteSection && realSiteLabel) {
  if (officialUrl) {
    // Replace {institution} placeholder in the label text
    const prefix = t('warning_real_site_prefix', lang)
      .replace('{institution}', institutionName || officialUrl);
    realSiteLabel.textContent = prefix;       // result of t() + safe replacement — textContent

    // Build the link
    const link = document.createElement('a');
    link.href            = officialUrl;         // value from params — safe as href (navigates away)
    link.textContent     = officialUrl;         // same untrusted value — textContent
    link.className       = 'real-site-link';
    link.target          = '_blank';
    link.rel             = 'noopener noreferrer';
    realSiteSection.appendChild(link);
  } else {
    realSiteLabel.textContent = t('warning_real_site_generic', lang);
    // No link to render
  }
}

// CAFC report line
// Build the sentence with {cafc} and {phone} replaced, then render as plain text.
// The link is a separate element to keep it keyboard-accessible.
const cafcText = t('warning_cafc_report', lang)
  .replace('{cafc}',  t('cafc_name',  lang))
  .replace('{phone}', t('cafc_phone', lang));
setText('cafc-text', cafcText);

const cafcLink = document.getElementById('cafc-link');
if (cafcLink) {
  cafcLink.href        = t('cafc_url', lang);
  cafcLink.textContent = t('cafc_url', lang)
    .replace(/^https?:\/\//, ''); // strip protocol for display only
}

// Disclaimer
setText('disclaimer', t('warning_disclaimer', lang));

// False-positive report — opens a prefilled GitHub issue via the service worker
const reportBtn = document.getElementById('report-fp');
if (reportBtn) {
  reportBtn.textContent = t('report_false_positive', lang);
  reportBtn.addEventListener('click', () => {
    try {
      chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_POSITIVE',
        kind: 'site',
        reportedUrl: url,
        verdict: 'high',
        reasons,
      });
    } catch { /* extension context unavailable */ }
  });
}

// Button labels
setText('btn-go-back', t('warning_go_back',  lang));
setText('btn-proceed',  t('warning_proceed', lang));

// ---------------------------------------------------------------------------
// Button behaviour
// ---------------------------------------------------------------------------

// Primary: go back to safety.
// We must NOT use history.back() here — the previous history entry is the
// flagged page itself, which would be re-analysed and bounce us straight back
// to this warning. Instead, ask the service worker to navigate this tab to a
// safe page (the New Tab page, falling back to about:blank).
document.getElementById('btn-go-back')?.addEventListener('click', () => {
  try {
    chrome.runtime.sendMessage({ type: 'GO_BACK_SAFE' });
  } catch {
    // Extension context unavailable — best-effort local fallback.
    window.location.replace('about:blank');
  }
});

// Secondary: proceed despite the warning.
// We must register a one-session override with the service worker BEFORE
// navigating, otherwise the service worker would immediately re-block the
// flagged URL and bounce the user back to this warning page.
document.getElementById('btn-proceed')?.addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ type: 'OVERRIDE_PROCEED', url });
  } catch {
    // If the message fails, fall back to a plain navigation. It may get
    // re-blocked, but that is safer than silently swallowing the click.
  }
  window.location.href = url;
});
