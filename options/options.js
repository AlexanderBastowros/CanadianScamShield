/**
 * options.js — Canadian Scam Shield settings page logic
 *
 * Responsibilities:
 *  - Load saved settings from chrome.storage.sync on open
 *  - Language radio: persist selection, show transient "Saved ✓" confirmation
 *  - Personal whitelist: validate domain input, add/remove entries, persist, re-render
 *  - Info section: version from manifest, privacy summary, CAFC link, Pro note
 *
 * Security note:
 *  - Whitelist domain strings come from user input and chrome.storage.
 *    All domain text is rendered via element.textContent — never innerHTML.
 */

import { t, detectLanguage } from '../lib/i18n.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Basic domain validation: lowercase letters, digits, dots, hyphens; min one dot; ≥2-char TLD */
const DOMAIN_REGEX = /^[a-z0-9.-]+\.[a-z]{2,}$/i;

/** How long the "Saved ✓" confirmation stays visible, in ms */
const SAVED_DISPLAY_MS = 2500;

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

/**
 * Normalise a raw domain input to a bare apex/subdomain string.
 * Strips leading protocol (http:// / https://) and leading www. prefix,
 * then trims whitespace and lowercases.
 *
 * @param {string} raw
 * @returns {string}
 */
function normaliseDomain(raw) {
  let d = raw.trim().toLowerCase();
  // Strip protocol
  d = d.replace(/^https?:\/\//i, '');
  // Strip leading www.
  d = d.replace(/^www\./i, '');
  // Strip trailing path/query/hash
  d = d.split('/')[0].split('?')[0].split('#')[0];
  return d;
}

// ---------------------------------------------------------------------------
// "Saved ✓" confirmation
// ---------------------------------------------------------------------------

let savedTimer = null;

/**
 * Show the transient "Saved ✓" confirmation, then auto-hide it.
 *
 * @param {string} lang
 */
function showSaved(lang) {
  const el = document.getElementById('saved-confirm');
  if (!el) return;

  setText(el, t('options_saved', lang));
  show(el);

  if (savedTimer) clearTimeout(savedTimer);
  savedTimer = setTimeout(() => hide(el), SAVED_DISPLAY_MS);
}

// ---------------------------------------------------------------------------
// Language section
// ---------------------------------------------------------------------------

/**
 * Set the radio button for the given language value.
 *
 * @param {'en'|'fr'} lang
 */
function setLanguageRadio(lang) {
  const radio = document.querySelector(`input[name="language"][value="${lang}"]`);
  if (radio) radio.checked = true;
}

/**
 * Wire the language radio group.
 * On change: persist to storage and show "Saved ✓".
 *
 * @param {string} currentLang  — the active language at page load
 */
function initLanguageSection(currentLang) {
  const radios = document.querySelectorAll('input[name="language"]');

  radios.forEach(radio => {
    radio.addEventListener('change', () => {
      if (!radio.checked) return;
      const newLang = radio.value;
      chrome.storage.sync.set({ language: newLang });
      showSaved(newLang);
    });
  });

  // Set the initial checked state
  setLanguageRadio(currentLang);
}

// ---------------------------------------------------------------------------
// Whitelist section
// ---------------------------------------------------------------------------

/**
 * Render the current whitelist entries into the <ul>.
 * Each entry gets a text node (textContent) + a Remove button.
 *
 * @param {string[]} whitelist
 * @param {string}   lang
 */
function renderWhitelist(whitelist, lang) {
  const list = document.getElementById('whitelist-list');
  if (!list) return;

  // Clear previous entries safely
  list.textContent = '';

  whitelist.forEach(domain => {
    const li = document.createElement('li');
    li.className = 'domain-list__item';

    // Domain text — textContent only (safe for untrusted data)
    const span = document.createElement('span');
    span.className = 'domain-list__domain';
    span.textContent = domain;  // never innerHTML

    // Remove button
    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn btn--remove';
    removeBtn.textContent = t('options_whitelist_remove', lang);
    removeBtn.setAttribute('aria-label', t('options_whitelist_remove', lang) + ': ' + domain);
    removeBtn.dataset.domain = domain;

    removeBtn.addEventListener('click', () => {
      chrome.storage.sync.get({ customWhitelist: [] }, result => {
        const updated = result.customWhitelist.filter(d => d !== domain);
        chrome.storage.sync.set({ customWhitelist: updated }, () => {
          renderWhitelist(updated, lang);
          showSaved(lang);
        });
      });
    });

    li.appendChild(span);
    li.appendChild(removeBtn);
    list.appendChild(li);
  });
}

/**
 * Wire the whitelist add-domain form.
 *
 * @param {string} lang
 */
function initWhitelistSection(lang) {
  const input    = document.getElementById('whitelist-input');
  const addBtn   = document.getElementById('whitelist-add-btn');
  const errorEl  = document.getElementById('whitelist-error');

  if (!input || !addBtn) return;

  // Set the placeholder via JS (no inline content in HTML)
  input.setAttribute('placeholder', t('options_whitelist_placeholder', lang));

  function handleAdd() {
    const raw = input.value;
    const domain = normaliseDomain(raw);

    // Validate
    if (!domain || !DOMAIN_REGEX.test(domain)) {
      setText(errorEl, 'Please enter a valid domain (e.g. example.com).');
      show(errorEl);
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }

    // Clear error state
    hide(errorEl);
    input.removeAttribute('aria-invalid');

    chrome.storage.sync.get({ customWhitelist: [] }, result => {
      const current = result.customWhitelist;

      // Deduplicate — don't add if already present
      if (current.includes(domain)) {
        setText(errorEl, `${domain} is already in your trusted sites list.`);
        show(errorEl);
        return;
      }

      const updated = [...current, domain];
      chrome.storage.sync.set({ customWhitelist: updated }, () => {
        renderWhitelist(updated, lang);
        input.value = '';
        showSaved(lang);
        input.focus();
      });
    });
  }

  addBtn.addEventListener('click', handleAdd);

  // Also submit on Enter key in the input
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAdd();
    }
  });
}

// ---------------------------------------------------------------------------
// Info section
// ---------------------------------------------------------------------------

/**
 * Populate the info section: version, privacy summary, CAFC link, Pro note.
 *
 * @param {string} lang
 */
function initInfoSection(lang) {
  // Version
  const versionLabel = document.getElementById('version-label');
  const versionValue = document.getElementById('version-value');
  const manifest = chrome.runtime.getManifest();

  setText(versionLabel, t('options_version', lang) + ' ');  // non-breaking space before value
  setText(versionValue, manifest.version);

  // Privacy summary
  setText(document.getElementById('privacy-summary'), t('options_privacy_summary', lang));

  // CAFC link
  const cafcLink = document.getElementById('cafc-link');
  if (cafcLink) {
    cafcLink.textContent = t('cafc_name', lang);
    cafcLink.href = t('cafc_url', lang);
  }

  // Pro coming soon note
  setText(document.getElementById('pro-coming-soon'), t('options_pro_coming_soon', lang));
}

// ---------------------------------------------------------------------------
// Static text population
// ---------------------------------------------------------------------------

/**
 * Populate all static text labels and headings from i18n.
 *
 * @param {string} lang
 */
function populateStaticText(lang) {
  // Page title
  setText(document.getElementById('page-title'), t('options_title', lang));
  document.title = t('options_title', lang);

  // Language section heading
  setText(document.getElementById('lang-heading'), t('options_language', lang));

  // Language radio labels
  setText(document.getElementById('label-lang-en'), t('options_lang_en', lang));
  setText(document.getElementById('label-lang-fr'), t('options_lang_fr', lang));

  // Whitelist section
  setText(document.getElementById('whitelist-heading'), t('options_whitelist_heading', lang));
  setText(document.getElementById('whitelist-desc'),    t('options_whitelist_desc', lang));
  setText(document.getElementById('whitelist-input-label'), t('options_whitelist_placeholder', lang));
  setText(document.getElementById('whitelist-add-btn'), t('options_whitelist_add', lang));
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

async function main() {
  const lang = await detectLanguage();

  // Populate static text first so the page renders text immediately
  populateStaticText(lang);

  // Wire the language radio group
  initLanguageSection(lang);

  // Wire the whitelist section (needs lang for button labels)
  initWhitelistSection(lang);

  // Populate info section
  initInfoSection(lang);

  // Load saved settings and apply them
  chrome.storage.sync.get({ language: 'en', customWhitelist: [] }, result => {
    // Apply the stored language (may differ from detectLanguage() if storage was already set)
    setLanguageRadio(result.language);

    // Render the current whitelist
    renderWhitelist(result.customWhitelist, lang);
  });
}

main();
