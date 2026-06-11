/**
 * onboarding/onboarding.js — first-run welcome screen.
 * Explains the extension, lets the user pick a language and confirm email
 * scanning, then sends them on their way. No inline scripts (MV3 CSP).
 */

import { t, detectLanguage } from '../lib/i18n.js';

function setText(id, str) {
  const el = document.getElementById(id);
  if (el) el.textContent = str;
}

/** (Re)render all copy in the given language. */
function render(lang) {
  document.documentElement.lang = lang;
  document.title = t('onboarding_title', lang);
  setText('brand', t('app_name', lang));
  setText('welcome', t('onboarding_welcome', lang));
  setText('intro', t('onboarding_intro', lang));

  setText('l1-title', t('onboarding_layer1_title', lang));
  setText('l1-desc', t('onboarding_layer1', lang));
  setText('l2-title', t('onboarding_layer2_title', lang));
  setText('l2-desc', t('onboarding_layer2', lang));
  setText('l3-title', t('onboarding_layer3_title', lang));
  setText('l3-desc', t('onboarding_layer3', lang));

  setText('privacy-title', t('onboarding_privacy_title', lang));
  setText('privacy-desc', t('onboarding_privacy', lang));

  setText('lang-title', t('onboarding_choose_language', lang));
  setText('lang-en-label', t('options_lang_en', lang));
  setText('lang-fr-label', t('options_lang_fr', lang));

  setText('mailscan-label', t('options_mail_scan', lang));
  setText('mailscan-note', t('options_mail_scan_note', lang));

  setText('done-btn', t('onboarding_done', lang));
  setText('settings-btn', t('onboarding_open_settings', lang));

  const cafc = document.getElementById('cafc-link');
  if (cafc) { cafc.textContent = t('cafc_name', lang); cafc.href = t('cafc_url', lang); }
}

async function main() {
  let lang = await detectLanguage();
  render(lang);

  // Language radios — persist and re-render live.
  const radio = document.querySelector(`input[name="language"][value="${lang}"]`);
  if (radio) radio.checked = true;
  document.querySelectorAll('input[name="language"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (!r.checked) return;
      lang = r.value;
      chrome.storage.sync.set({ language: lang });
      render(lang);
    });
  });

  // Mail-scan consent (default on).
  const mailToggle = document.getElementById('mailscan-toggle');
  chrome.storage.sync.get({ mailScanEnabled: true }, (s) => { mailToggle.checked = s.mailScanEnabled; });
  mailToggle.addEventListener('change', () => {
    chrome.storage.sync.set({ mailScanEnabled: mailToggle.checked });
  });

  // Actions.
  document.getElementById('done-btn').addEventListener('click', () => {
    chrome.storage.local.set({ onboarded: true });
    window.close();
  });
  document.getElementById('settings-btn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
}

main();
