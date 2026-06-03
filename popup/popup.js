/**
 * popup.js — Canadian Scam Shield popup logic
 *
 * Responsibilities:
 *  - Detect active tab URL; show status panel or unknown state
 *  - Send GET_STATUS to service worker; render verdict
 *  - Tab switching between "This site" and "Check a message"
 *  - Footer: open options page; open CAFC link
 *
 * Security notes:
 *  - institutionName and reasons[] come from untrusted page data.
 *    Always set via element.textContent, never innerHTML.
 */

import { t, detectLanguage } from '../lib/i18n.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Set element text via textContent (safe for untrusted strings). */
function setText(el, str) {
  if (el) el.textContent = str;
}

/** Show an element (remove hidden attribute). */
function show(el) {
  if (el) el.removeAttribute('hidden');
}

/** Hide an element (set hidden attribute). */
function hide(el) {
  if (el) el.setAttribute('hidden', '');
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function initTabs() {
  const tabStatus = document.getElementById('tab-status');
  const tabCheck  = document.getElementById('tab-check');
  const panelStatus = document.getElementById('panel-status');
  const panelCheck  = document.getElementById('panel-check');

  function activateTab(activeTab, activePanel, inactiveTab, inactivePanel) {
    activeTab.classList.add('is-active');
    activeTab.setAttribute('aria-selected', 'true');
    inactiveTab.classList.remove('is-active');
    inactiveTab.setAttribute('aria-selected', 'false');
    show(activePanel);
    hide(inactivePanel);
  }

  tabStatus.addEventListener('click', () => {
    activateTab(tabStatus, panelStatus, tabCheck, panelCheck);
  });

  tabCheck.addEventListener('click', () => {
    activateTab(tabCheck, panelCheck, tabStatus, panelStatus);
  });
}

// ---------------------------------------------------------------------------
// Verdict rendering
// ---------------------------------------------------------------------------

/**
 * Determine if a URL is a web page we can analyse.
 * chrome://, about:, moz-extension://, etc. return false.
 */
function isAnalysableUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Render the unknown / non-web state.
 * Called when the active tab is a browser-internal page.
 */
function renderUnknown(lang) {
  const loadingEl = document.getElementById('status-loading');
  const resultEl  = document.getElementById('status-result');

  hide(loadingEl);
  show(resultEl);

  const indicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('status-text');

  setText(indicator, 'ℹ️');
  setText(statusText, t('popup_status_unknown', lang));
  statusText.className = 'status-text status-text--unknown';

  // No why section for unknown state
  hide(document.getElementById('why-section'));
}

/**
 * Render the verdict returned by the service worker.
 *
 * @param {{ verdict: string, score: number, reasons: string[],
 *           officialUrl: string|null, institutionName: string|null }} result
 * @param {string} lang
 */
function renderVerdict(result, lang) {
  const loadingEl = document.getElementById('status-loading');
  const resultEl  = document.getElementById('status-result');

  hide(loadingEl);
  show(resultEl);

  const { verdict, reasons = [], institutionName } = result;

  const indicator  = document.getElementById('status-indicator');
  const statusText = document.getElementById('status-text');
  const detailEl   = document.getElementById('status-detail');
  const whySection = document.getElementById('why-section');

  // --- indicator + status text ---
  if (verdict === 'safe') {
    setText(indicator, '✅');
    setText(statusText, t('popup_status_safe', lang));
    statusText.className = 'status-text status-text--safe';

    // Safe detail line — uses institutionName from untrusted content
    if (institutionName) {
      const detailTemplate = t('popup_safe_detail', lang);   // "Recognized as {name}."
      // Build the text manually so we never write HTML
      const detailText = detailTemplate.replace('{name}', String(institutionName));
      setText(detailEl, detailText);
      show(detailEl);
    }

    hide(whySection);

  } else if (verdict === 'low' || verdict === 'medium') {
    setText(indicator, '⚠️');
    setText(statusText, t('popup_status_caution', lang));
    statusText.className = 'status-text status-text--caution';
    renderWhySection(reasons, lang);
    show(whySection);

  } else if (verdict === 'high') {
    setText(indicator, '🚫');
    setText(statusText, t('popup_status_flagged', lang));
    statusText.className = 'status-text status-text--flagged';
    renderWhySection(reasons, lang);
    show(whySection);

  } else {
    // Unexpected verdict — fall back to unknown
    renderUnknown(lang);
  }
}

/**
 * Populate and wire the Why? accordion.
 * reasons[] items come from the service worker and must be treated as untrusted.
 *
 * @param {string[]} reasons
 * @param {string} lang
 */
function renderWhySection(reasons, lang) {
  const whyBtn      = document.getElementById('why-btn');
  const reasonsPanel = document.getElementById('reasons-panel');
  const reasonsList  = document.getElementById('reasons-list');
  const reasonsHeading = document.getElementById('reasons-heading');

  setText(whyBtn, t('popup_why', lang));
  setText(reasonsHeading, t('popup_top_reasons', lang));

  // Clear any previous entries
  reasonsList.textContent = '';

  if (reasons.length > 0) {
    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = String(reason);   // textContent — safe for untrusted input
      reasonsList.appendChild(li);
    });
  }

  // Wire toggle — remove old listener by replacing the button clone
  const newBtn = whyBtn.cloneNode(true);
  // Restore the label (cloneNode copies content already set above)
  whyBtn.parentNode.replaceChild(newBtn, whyBtn);

  newBtn.addEventListener('click', () => {
    const expanded = newBtn.getAttribute('aria-expanded') === 'true';
    newBtn.setAttribute('aria-expanded', String(!expanded));
    if (expanded) {
      hide(reasonsPanel);
    } else {
      show(reasonsPanel);
    }
  });
}

// ---------------------------------------------------------------------------
// Footer wiring
// ---------------------------------------------------------------------------

function initFooter(lang) {
  const btnOptions = document.getElementById('btn-options');
  const btnCafc    = document.getElementById('btn-cafc');

  setText(btnOptions, t('popup_open_options', lang));
  setText(btnCafc, t('popup_cafc_link', lang));

  btnOptions.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  btnCafc.addEventListener('click', () => {
    chrome.tabs.create({ url: t('cafc_url', lang) });
  });
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

async function main() {
  const lang = await detectLanguage();

  // Set static text
  setText(document.getElementById('app-name'), t('app_name', lang));
  setText(document.getElementById('tab-status'), t('popup_tab_status', lang));
  setText(document.getElementById('tab-check'), t('popup_tab_check', lang));
  setText(document.getElementById('check-coming-soon'), t('popup_check_coming_soon', lang));

  // Pre-populate the why-btn label so it renders even before a verdict
  setText(document.getElementById('why-btn'), t('popup_why', lang));

  initTabs();
  initFooter(lang);

  // Query the active tab
  let activeTab;
  try {
    [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    renderUnknown(lang);
    return;
  }

  if (!activeTab?.url || !isAnalysableUrl(activeTab.url)) {
    renderUnknown(lang);
    return;
  }

  // Ask the service worker for the verdict
  let response;
  try {
    response = await chrome.runtime.sendMessage({
      type: 'GET_STATUS',
      url: activeTab.url,
    });
  } catch {
    // Service worker not ready or threw — show unknown
    renderUnknown(lang);
    return;
  }

  if (!response) {
    renderUnknown(lang);
    return;
  }

  renderVerdict(response, lang);
}

main();
