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
// Check a message tab (Layer 3)
// ---------------------------------------------------------------------------

/**
 * Populates the static labels of the message-checker tab and wires the
 * "Check it" flow against the service worker's CHECK_MESSAGE route.
 *
 * SECURITY: every dynamic value coming back from the analyzer (explanations,
 * contact info) is rendered via textContent — never innerHTML.
 */
function initChecker(lang) {
  const heading   = document.getElementById('check-heading');
  const instr     = document.getElementById('check-instructions');
  const sendLabel = document.getElementById('check-sender-label');
  const sender    = document.getElementById('check-sender');
  const textarea  = document.getElementById('check-textarea');
  const errorEl   = document.getElementById('check-error');
  const btn       = document.getElementById('check-btn');
  const results   = document.getElementById('check-results');

  setText(heading, t('check_heading', lang));
  setText(instr, t('check_instructions', lang));
  setText(sendLabel, t('check_sender_label', lang));
  sender.placeholder = t('check_sender_placeholder', lang);
  textarea.placeholder = t('check_textarea_placeholder', lang);
  setText(btn, t('check_button', lang));
  setText(document.getElementById('check-result-heading'), t('check_result_heading', lang));
  setText(document.getElementById('check-score-label'), t('check_score_label', lang));
  setText(document.getElementById('check-rules-heading'), t('check_fired_rules_heading', lang));
  setText(document.getElementById('check-upgrade-hint'), t('popup_upgrade_hint', lang));

  async function runCheck() {
    const rawText = textarea.value.trim();
    if (!rawText) {
      setText(errorEl, t('check_empty_error', lang));
      show(errorEl);
      hide(results);
      return;
    }
    hide(errorEl);
    btn.disabled = true;
    setText(btn, t('check_checking', lang));

    let res;
    try {
      const msg = { type: 'CHECK_MESSAGE', rawText };
      const senderVal = sender.value.trim();
      if (senderVal) msg.sender = senderVal;
      res = await chrome.runtime.sendMessage(msg);
    } catch {
      res = null;
    }
    btn.disabled = false;
    setText(btn, t('check_button', lang));

    if (!res) {
      setText(errorEl, t('check_generic_error', lang));
      show(errorEl);
      hide(results);   // don't leave a previous check's results under the error
      return;
    }
    renderCheckResult(res, lang);
    show(results);
  }

  btn.addEventListener('click', runCheck);
  textarea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runCheck();
  });
}

/** Renders one CHECK_MESSAGE response into the results section. */
function renderCheckResult(res, lang) {
  const { score = 0, verdict = 'safe', firedRules = [], officialContact = null } = res;

  // Score meter
  setText(document.getElementById('score-value'), String(score));
  const fill = document.getElementById('score-bar-fill');
  fill.style.width = score + '%';
  fill.className = 'score-bar-fill score-fill--' + verdict;

  // Verdict badge + advice
  const verdictEl = document.getElementById('check-verdict');
  setText(verdictEl, t('check_verdict_' + verdict, lang));
  verdictEl.className = 'check-verdict check-verdict--' + verdict;
  setText(
    document.getElementById('check-advice'),
    verdict === 'safe' ? t('check_advice_safe', lang) : t('check_advice_caution', lang)
  );

  // Fired rules — explanations are data-driven text; render via textContent
  const rulesHeading = document.getElementById('check-rules-heading');
  const rulesList = document.getElementById('check-rules-list');
  rulesList.textContent = '';
  if (firedRules.length > 0) {
    show(rulesHeading); show(rulesList);
    firedRules.forEach((rule) => {
      const li = document.createElement('li');
      li.textContent = String(rule.explanation || rule.id);
      rulesList.appendChild(li);
    });
  } else {
    hide(rulesHeading); hide(rulesList);
  }

  // Official contact (from known-sender-domains.json — trusted data, still textContent)
  const contact = document.getElementById('check-contact');
  const contactLabel = document.getElementById('check-contact-label');
  const contactLink = document.getElementById('check-contact-link');
  const contactPhone = document.getElementById('check-contact-phone');
  if (officialContact && (officialContact.url || officialContact.phone)) {
    setText(contactLabel,
      t('check_official_contact', lang).replace('{name}', String(officialContact.name || '')));
    if (officialContact.url) {
      contactLink.href = officialContact.url;
      contactLink.textContent = officialContact.url;
      show(contactLink);
    } else {
      hide(contactLink);
    }
    if (officialContact.phone) {
      contactPhone.textContent = officialContact.phone;
      show(contactPhone);
    } else {
      hide(contactPhone);
    }
    show(contact);
  } else {
    hide(contact);
  }
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
  setText(document.getElementById('sr-checking'), t('sr_checking_site', lang));
  document.querySelector('.tabs')?.setAttribute('aria-label', t('aria_popup_nav', lang));

  // Pre-populate the why-btn label so it renders even before a verdict
  setText(document.getElementById('why-btn'), t('popup_why', lang));

  initTabs();
  initChecker(lang);
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
