/**
 * lib/i18n.js — Bilingual string system for Canadian Scam Shield
 *
 * Exports:
 *   strings       — flat key→string map per language ({ en: {...}, fr: {...} })
 *   getStrings(lang)  — returns strings[lang] or strings.en
 *   t(key, lang)      — returns translated string, falls back to en, then to key itself
 *   detectLanguage()  — async; reads chrome.storage.sync, then navigator.language, defaults 'en'
 *
 * FR note: French strings are intentionally stubbed for Phase 1.
 * Only app_name, cafc_name, and warning_heading have FR translations.
 * All other keys fall back to English via t(). Full FR translation is Phase 2.
 */

// ---------------------------------------------------------------------------
// English strings (complete)
// ---------------------------------------------------------------------------

const en = {

  // -------------------------------------------------------------------------
  // Common
  // -------------------------------------------------------------------------
  app_name:   'Canadian Scam Shield',
  cafc_name:  'Canadian Anti-Fraud Centre',
  cafc_phone: '1-888-495-8501',
  cafc_url:   'https://antifraudcentre-centreantifraude.ca',

  // -------------------------------------------------------------------------
  // Warning page (full-page block — warning/warning.html)
  // -------------------------------------------------------------------------

  /** Browser tab <title> */
  warning_title: 'Warning — Canadian Scam Shield',

  /** Large H1 shown to the user */
  warning_heading: 'This site may be trying to scam you',

  /** One calm sentence below the heading — not a guarantee, just a flag */
  warning_subheading:
    'Canadian Scam Shield noticed something unusual about this address. '
    + 'We may be wrong, but it is worth being careful before you go any further.',

  /** Label preceding the suspicious URL */
  warning_url_label: 'The site you tried to open:',

  /** Section heading for the reasons list */
  warning_why_flagged: 'Why we flagged this',

  /**
   * Used when we know which institution is being impersonated.
   * {institution} is replaced at render time with the institution name.
   * Example: "Looking for Canada Revenue Agency? The real website is:"
   */
  warning_real_site_prefix: 'Looking for {institution}? The real website is:',

  /** Shown when no specific institution is identified */
  warning_real_site_generic:
    'If you were looking for an official Canadian organization, '
    + 'type its address yourself or search for it on a trusted search engine.',

  /**
   * CAFC report prompt at the bottom of the warning page.
   * {cafc} → cafc_name, {phone} → cafc_phone (substituted at render time).
   */
  warning_cafc_report:
    'If you think this is a scam, you can report it to the {cafc} at {phone}.',

  /** Primary action button — takes user back */
  warning_go_back: 'Go back to safety',

  /** Secondary action button — explicit override */
  warning_proceed: 'I understand the risk, continue anyway',

  /** Small-print disclaimer below the buttons */
  warning_disclaimer:
    'Canadian Scam Shield helps you spot potential scams, but it cannot catch '
    + 'everything. Use your own judgement — if something feels wrong, trust that feeling.',

  // -------------------------------------------------------------------------
  // Popup (popup/popup.html + popup.js)
  // -------------------------------------------------------------------------

  /** Tab label — current-site status tab */
  popup_tab_status: 'This site',

  /** Tab label — paste checker tab */
  popup_tab_check: 'Check a message',

  /** Status line when site is whitelisted / clean */
  popup_status_safe: 'This site looks safe',

  /**
   * Detail line under the safe status.
   * {name} is replaced with the institution name from whitelist.json.
   * Example: "Recognized as Royal Bank of Canada."
   */
  popup_safe_detail: 'Recognized as {name}.',

  /** Status line for medium-confidence suspicion */
  popup_status_caution: 'Be careful with this site',

  /** Status line when site scored high */
  popup_status_flagged: 'This site looks suspicious',

  /** Status line when site is unrecognized but not flagged */
  popup_status_unknown: "We don't have information about this site",

  /** Link/button to expand the reasons accordion */
  popup_why: 'Why?',

  /** Section heading for the reasons list in the popup */
  popup_top_reasons: 'What we noticed',

  /** Button to open the options/settings page */
  popup_open_options: 'Settings',

  /** Link to CAFC reporting page */
  popup_cafc_link: 'Report a scam',

  /** Placeholder text in the Check a message tab */
  popup_check_coming_soon:
    'The email and text message checker is coming soon.',

  // -------------------------------------------------------------------------
  // Content banner (medium confidence — injected by content-script.js)
  // -------------------------------------------------------------------------

  /** Banner text at medium confidence (score 55–79) */
  banner_caution:
    'Canadian Scam Shield: this site looks suspicious. '
    + 'Be careful before entering any personal information.',

  /** Dismiss button on the banner */
  banner_dismiss: 'Dismiss',

  /** "Why?" link on the banner — opens popup or warning detail */
  banner_learn_more: 'Why?',

  // -------------------------------------------------------------------------
  // Options page (options/options.html + options.js)
  // -------------------------------------------------------------------------

  /** Browser tab <title> and page heading */
  options_title: 'Canadian Scam Shield — Settings',

  /** Language section label */
  options_language: 'Language',

  /** English radio-button label */
  options_lang_en: 'English',

  /** French radio-button label */
  options_lang_fr: 'Français',

  /** Trusted sites section heading */
  options_whitelist_heading: 'Your trusted sites',

  /** Description text under the trusted sites heading */
  options_whitelist_desc:
    'Add websites you personally trust so they’re never flagged.',

  /** Add button for the trusted-sites list */
  options_whitelist_add: 'Add',

  /** Placeholder text for the trusted-sites input field */
  options_whitelist_placeholder: 'example.com',

  /** Remove button for each trusted-site entry */
  options_whitelist_remove: 'Remove',

  /** Inline confirmation shown after saving */
  options_saved: 'Saved ✓',

  /** Version label (value appended at runtime) */
  options_version: 'Version',

  /**
   * Privacy summary paragraph shown in the info section.
   * One paragraph, plain language.
   */
  options_privacy_summary:
    'All analysis runs locally on your device. In the free version, '
    + 'no browsing data, URLs, or messages are sent to any server. '
    + 'There is no tracking, no analytics, and no account required.',

  /** Teaser for Shield Pro sensitivity controls */
  options_pro_coming_soon:
    'More controls (sensitivity, custom blocklist) are coming with Shield Pro.',

};

// ---------------------------------------------------------------------------
// French strings (intentionally stubbed — Phase 1)
//
// Only the keys below have confirmed FR translations for Phase 1.
// All other keys are omitted here; t() will fall back to the EN value.
// Full FR translation is scheduled for Phase 2.
// ---------------------------------------------------------------------------

const fr = {

  // Common
  app_name:  'Canadian Scam Shield',        // brand name — keep in English
  cafc_name: 'Centre antifraude du Canada',

  // Warning page
  warning_heading: 'Ce site tente peut-être de vous escroquer',

};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * The complete string maps.
 * @type {{ en: Record<string, string>, fr: Record<string, string> }}
 */
export const strings = { en, fr };

/**
 * Returns the string map for the requested language.
 * Falls back to English for any unknown language code.
 *
 * @param {string} lang - 'en' or 'fr'
 * @returns {Record<string, string>}
 */
export function getStrings(lang) {
  return strings[lang] ?? strings.en;
}

/**
 * Returns a single translated string.
 * Resolution order:
 *   1. strings[lang][key]
 *   2. strings.en[key]
 *   3. key itself (so missing keys are visible but don't crash)
 *
 * @param {string} key
 * @param {string} [lang='en']
 * @returns {string}
 */
export function t(key, lang = 'en') {
  return strings[lang]?.[key] ?? strings.en[key] ?? key;
}

/**
 * Detects the user's preferred language.
 *
 * Resolution order:
 *   1. chrome.storage.sync 'language' value (if 'en' or 'fr')
 *   2. navigator.language (returns 'fr' if starts with 'fr', else 'en')
 *   3. 'en'
 *
 * Safe to call in Node (chrome and navigator may both be undefined).
 *
 * @returns {Promise<'en'|'fr'>}
 */
export async function detectLanguage() {
  // 1. Check extension storage (user's explicit preference)
  if (typeof chrome !== 'undefined' && chrome.storage?.sync) {
    try {
      const result = await chrome.storage.sync.get('language');
      const stored = result?.language;
      if (stored === 'en' || stored === 'fr') {
        return stored;
      }
    } catch {
      // Storage read failed — fall through to navigator check
    }
  }

  // 2. Fall back to browser language
  if (typeof navigator !== 'undefined') {
    return navigator.language?.startsWith('fr') ? 'fr' : 'en';
  }

  // 3. Default
  return 'en';
}
