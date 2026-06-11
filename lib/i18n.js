/**
 * lib/i18n.js — Bilingual string system for Canadian Scam Shield
 *
 * Exports:
 *   strings       — flat key→string map per language ({ en: {...}, fr: {...} })
 *   getStrings(lang)  — returns strings[lang] or strings.en
 *   t(key, lang)      — returns translated string, falls back to en, then to key itself
 *   detectLanguage()  — async; reads chrome.storage.sync, then navigator.language, defaults 'en'
 *
 * Both maps are complete — every EN key has an FR counterpart (Canadian
 * French, vouvoiement, Grade-8 reading level).
 */

// ---------------------------------------------------------------------------
// English strings
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

  popup_tab_status: 'This site',
  popup_tab_check: 'Check a message',
  popup_status_safe: 'This site looks safe',
  popup_safe_detail: 'Recognized as {name}.',
  popup_status_caution: 'Be careful with this site',
  popup_status_flagged: 'This site looks suspicious',
  popup_status_unknown: "We don't have information about this site",
  popup_why: 'Why?',
  popup_top_reasons: 'What we noticed',
  popup_open_options: 'Settings',
  popup_cafc_link: 'Report a scam',
  popup_check_coming_soon: 'The email and text message checker is coming soon.',
  popup_pro_badge: 'PRO',
  popup_upgrade_hint:
    'Want deeper checks (domain age, live phishing feeds)? See Shield Pro in Settings.',

  // -------------------------------------------------------------------------
  // Popup — Check a message tab (Layer 3)
  // -------------------------------------------------------------------------

  check_heading: 'Check a suspicious message',
  check_instructions:
    "Paste an email or text message below and we'll look for common scam signs.",
  check_sender_label: 'Sender (optional)',
  check_sender_placeholder: 'name@example.com or the From line',
  check_textarea_placeholder: 'Paste the message here',
  check_button: 'Check it',
  check_checking: 'Checking…',
  check_result_heading: 'What we found',
  check_score_label: 'Risk score',
  check_verdict_safe: 'No obvious scam signs',
  check_verdict_low: 'A few things to watch',
  check_verdict_medium: 'This looks suspicious',
  check_verdict_high: 'This looks like a scam',
  check_fired_rules_heading: 'Why',
  /** {name} replaced with the organization name at render time */
  check_official_contact: 'If you want to confirm, contact {name} directly:',
  check_advice_safe:
    "We didn't spot common scam patterns. Still, if something feels off, trust that feeling.",
  check_advice_caution:
    'Do not click links, call numbers, or send money or codes from this message. '
    + 'Contact the organization using a number you find yourself.',
  check_empty_error: 'Paste a message first.',

  // -------------------------------------------------------------------------
  // Content banner (medium confidence — injected by content-script.js)
  // -------------------------------------------------------------------------

  banner_caution:
    'Canadian Scam Shield: this site looks suspicious. '
    + 'Be careful before entering any personal information.',
  banner_dismiss: 'Dismiss',
  banner_learn_more: 'Why?',

  // -------------------------------------------------------------------------
  // Options page (options/options.html + options.js)
  // -------------------------------------------------------------------------

  options_title: 'Canadian Scam Shield — Settings',
  options_language: 'Language',
  options_lang_en: 'English',
  options_lang_fr: 'Français',
  options_whitelist_heading: 'Your trusted sites',
  options_whitelist_desc:
    'Add websites you personally trust so they’re never flagged.',
  options_whitelist_add: 'Add',
  options_whitelist_placeholder: 'example.com',
  options_whitelist_remove: 'Remove',
  options_saved: 'Saved ✓',
  options_version: 'Version',
  options_privacy_summary:
    'All analysis runs locally on your device. In the free version, '
    + 'no browsing data, URLs, or messages are sent to any server. '
    + 'There is no tracking, no analytics, and no account required.',
  options_pro_coming_soon:
    'More controls (sensitivity, custom blocklist) are coming with Shield Pro.',

  // -------------------------------------------------------------------------
  // Options — Shield Pro section
  // -------------------------------------------------------------------------

  options_pro_heading: 'Shield Pro',
  options_pro_desc:
    'Extra protection for $3.99/month: live threat feeds, domain age checks, '
    + 'sensitivity controls, and custom block lists.',
  options_pro_upgrade: 'Upgrade to Shield Pro',
  options_pro_license_label: 'License key',
  options_pro_license_placeholder: 'CSS-XXXX-XXXX-XXXX-XXXX',
  options_pro_activate: 'Activate',
  options_pro_active: 'Shield Pro is active ✓',
  options_pro_inactive: 'License inactive or invalid',
  options_pro_checking: 'Checking license…',
  options_sensitivity: 'Sensitivity',
  options_sensitivity_desc: 'How cautious should warnings be?',
  options_sensitivity_strict: 'Strict — warn more often',
  options_sensitivity_balanced: 'Balanced — recommended',
  options_sensitivity_permissive: 'Permissive — warn less often',
  options_blocklist_heading: 'Your blocked sites',
  options_blocklist_desc: 'Sites you never want to load without a warning.',
  options_phishtank: 'Check suspicious sites against PhishTank',
  options_phishtank_note:
    'When on, suspicious site addresses are sent to PhishTank to check '
    + 'against known phishing sites.',
  options_phishtank_key: 'PhishTank app key',
  options_phishtank_key_placeholder: 'Your PhishTank app key',
  options_pro_locked: 'Shield Pro feature',
  options_data_updated: 'Threat data last updated',
  options_update_now: 'Update now',

  // Email scanning (Gmail / Outlook)
  options_mail_scan: 'Scan emails I open in Gmail and Outlook',
  options_mail_scan_note:
    'When on, Canadian Scam Shield checks the email you currently have open and '
    + 'shows a warning if it looks like a scam. The email is analyzed on your '
    + 'device and is never sent anywhere.',
  mail_chip_safe: 'No obvious scam signs',
  mail_scan_button: 'Scan this email',
  mail_no_email:
    'Couldn’t find an open email. Select the message text, then click “Scan this email” again.',

  // False-positive reporting
  report_false_positive: 'This isn’t a scam — report it',
  report_short: 'Report a mistake',

  // Onboarding (first run)
  onboarding_title: 'Welcome to Canadian Scam Shield',
  onboarding_welcome: 'You’re protected. Here’s what that means.',
  onboarding_intro:
    'Canadian Scam Shield quietly watches for scams that pretend to be Canadian '
    + 'organizations like the CRA, your bank, or Canada Post. It works in the '
    + 'background — you only hear from it when something looks wrong.',
  onboarding_layer1_title: 'Fake websites',
  onboarding_layer1: 'It warns you about look-alike and fake Canadian websites before you trust them.',
  onboarding_layer2_title: 'Scam pages',
  onboarding_layer2: 'It checks the page you’re on for the tricks scammers use, like fake refund or payment demands.',
  onboarding_layer3_title: 'Suspicious emails and texts',
  onboarding_layer3: 'Paste any email or text into the popup to check it — or let it check the emails you open in Gmail and Outlook.',
  onboarding_privacy_title: 'Your privacy',
  onboarding_privacy:
    'Everything is checked right here on your device. Your browsing and your '
    + 'emails are never sent to us or anyone else.',
  onboarding_choose_language: 'Choose your language',
  onboarding_done: 'Get started',
  onboarding_open_settings: 'Open settings',

};

// ---------------------------------------------------------------------------
// French strings (complete — Canadian French, vouvoiement)
// ---------------------------------------------------------------------------

const fr = {

  // Common
  app_name:   'Canadian Scam Shield',        // brand name — keep in English
  cafc_name:  'Centre antifraude du Canada',
  cafc_phone: '1-888-495-8501',
  cafc_url:   'https://antifraudcentre-centreantifraude.ca',

  // Warning page
  warning_title: 'Avertissement — Canadian Scam Shield',
  warning_heading: 'Ce site tente peut-être de vous escroquer',
  warning_subheading:
    'Canadian Scam Shield a remarqué quelque chose d’inhabituel à propos de '
    + 'cette adresse. Nous pouvons nous tromper, mais il vaut mieux être '
    + 'prudent avant d’aller plus loin.',
  warning_url_label: 'Le site que vous avez tenté d’ouvrir :',
  warning_why_flagged: 'Pourquoi nous l’avons signalé',
  warning_real_site_prefix:
    'Vous cherchez {institution}? Le vrai site Web est :',
  warning_real_site_generic:
    'Si vous cherchiez un organisme canadien officiel, tapez son adresse '
    + 'vous-même ou recherchez-la sur un moteur de recherche fiable.',
  warning_cafc_report:
    'Si vous pensez qu’il s’agit d’une fraude, vous pouvez la signaler au '
    + '{cafc} au {phone}.',
  warning_go_back: 'Retourner en sécurité',
  warning_proceed: 'Je comprends le risque, continuer quand même',
  warning_disclaimer:
    'Canadian Scam Shield vous aide à repérer les fraudes possibles, mais il '
    + 'ne peut pas tout détecter. Fiez-vous à votre jugement — si quelque '
    + 'chose vous semble louche, écoutez ce sentiment.',

  // Popup
  popup_tab_status: 'Ce site',
  popup_tab_check: 'Vérifier un message',
  popup_status_safe: 'Ce site semble sûr',
  popup_safe_detail: 'Reconnu comme {name}.',
  popup_status_caution: 'Soyez prudent avec ce site',
  popup_status_flagged: 'Ce site semble suspect',
  popup_status_unknown: 'Nous n’avons pas d’information sur ce site',
  popup_why: 'Pourquoi?',
  popup_top_reasons: 'Ce que nous avons remarqué',
  popup_open_options: 'Paramètres',
  popup_cafc_link: 'Signaler une fraude',
  popup_check_coming_soon:
    'Le vérificateur de courriels et de messages texte arrive bientôt.',
  popup_pro_badge: 'PRO',
  popup_upgrade_hint:
    'Vous voulez des vérifications plus poussées (âge du domaine, listes de '
    + 'hameçonnage en direct)? Consultez Shield Pro dans les paramètres.',

  // Popup — Check a message tab
  check_heading: 'Vérifier un message suspect',
  check_instructions:
    'Collez un courriel ou un message texte ci-dessous et nous chercherons '
    + 'les signes de fraude courants.',
  check_sender_label: 'Expéditeur (facultatif)',
  check_sender_placeholder: 'nom@exemple.com ou la ligne « De »',
  check_textarea_placeholder: 'Collez le message ici',
  check_button: 'Vérifier',
  check_checking: 'Vérification…',
  check_result_heading: 'Ce que nous avons trouvé',
  check_score_label: 'Niveau de risque',
  check_verdict_safe: 'Aucun signe de fraude évident',
  check_verdict_low: 'Quelques éléments à surveiller',
  check_verdict_medium: 'Ce message semble suspect',
  check_verdict_high: 'Ce message ressemble à une fraude',
  check_fired_rules_heading: 'Pourquoi',
  check_official_contact:
    'Pour confirmer, communiquez directement avec {name} :',
  check_advice_safe:
    'Nous n’avons pas repéré de signes de fraude courants. Malgré tout, si '
    + 'quelque chose vous semble louche, écoutez ce sentiment.',
  check_advice_caution:
    'Ne cliquez pas sur les liens, n’appelez pas les numéros et n’envoyez ni '
    + 'argent ni codes à partir de ce message. Communiquez avec l’organisme '
    + 'en utilisant un numéro que vous trouvez vous-même.',
  check_empty_error: 'Collez d’abord un message.',

  // Content banner
  banner_caution:
    'Canadian Scam Shield : ce site semble suspect. Soyez prudent avant '
    + 'd’entrer des renseignements personnels.',
  banner_dismiss: 'Fermer',
  banner_learn_more: 'Pourquoi?',

  // Options page
  options_title: 'Canadian Scam Shield — Paramètres',
  options_language: 'Langue',
  options_lang_en: 'English',
  options_lang_fr: 'Français',
  options_whitelist_heading: 'Vos sites de confiance',
  options_whitelist_desc:
    'Ajoutez les sites Web auxquels vous faites confiance pour qu’ils ne '
    + 'soient jamais signalés.',
  options_whitelist_add: 'Ajouter',
  options_whitelist_placeholder: 'exemple.com',
  options_whitelist_remove: 'Retirer',
  options_saved: 'Enregistré ✓',
  options_version: 'Version',
  options_privacy_summary:
    'Toute l’analyse se fait localement sur votre appareil. Dans la version '
    + 'gratuite, aucune donnée de navigation, adresse ou message n’est envoyé '
    + 'à un serveur. Pas de suivi, pas de statistiques, pas de compte requis.',
  options_pro_coming_soon:
    'D’autres contrôles (sensibilité, liste de blocage personnalisée) '
    + 'arrivent avec Shield Pro.',

  // Options — Shield Pro section
  options_pro_heading: 'Shield Pro',
  options_pro_desc:
    'Une protection accrue pour 3,99 $/mois : listes de menaces en direct, '
    + 'vérification de l’âge des domaines, contrôles de sensibilité et listes '
    + 'de blocage personnalisées.',
  options_pro_upgrade: 'Passer à Shield Pro',
  options_pro_license_label: 'Clé de licence',
  options_pro_license_placeholder: 'CSS-XXXX-XXXX-XXXX-XXXX',
  options_pro_activate: 'Activer',
  options_pro_active: 'Shield Pro est actif ✓',
  options_pro_inactive: 'Licence inactive ou invalide',
  options_pro_checking: 'Vérification de la licence…',
  options_sensitivity: 'Sensibilité',
  options_sensitivity_desc: 'À quel point les avertissements doivent-ils être prudents?',
  options_sensitivity_strict: 'Stricte — avertir plus souvent',
  options_sensitivity_balanced: 'Équilibrée — recommandée',
  options_sensitivity_permissive: 'Permissive — avertir moins souvent',
  options_blocklist_heading: 'Vos sites bloqués',
  options_blocklist_desc:
    'Les sites que vous ne voulez jamais ouvrir sans avertissement.',
  options_phishtank: 'Vérifier les sites suspects auprès de PhishTank',
  options_phishtank_note:
    'Lorsque cette option est activée, les adresses des sites suspects sont '
    + 'envoyées à PhishTank pour vérification contre les sites d’hameçonnage connus.',
  options_phishtank_key: 'Clé d’application PhishTank',
  options_phishtank_key_placeholder: 'Votre clé d’application PhishTank',
  options_pro_locked: 'Fonction Shield Pro',
  options_data_updated: 'Dernière mise à jour des données',
  options_update_now: 'Mettre à jour maintenant',

  // Email scanning (Gmail / Outlook)
  options_mail_scan: 'Analyser les courriels que j’ouvre dans Gmail et Outlook',
  options_mail_scan_note:
    'Lorsque cette option est activée, Canadian Scam Shield vérifie le courriel '
    + 'que vous avez ouvert et affiche un avertissement s’il ressemble à une '
    + 'fraude. Le courriel est analysé sur votre appareil et n’est jamais envoyé '
    + 'ailleurs.',
  mail_chip_safe: 'Aucun signe de fraude évident',
  mail_scan_button: 'Analyser ce courriel',
  mail_no_email:
    'Impossible de trouver un courriel ouvert. Sélectionnez le texte du message, '
    + 'puis cliquez de nouveau sur « Analyser ce courriel ».',

  // False-positive reporting
  report_false_positive: 'Ce n’est pas une fraude — signalez-le',
  report_short: 'Signaler une erreur',

  // Onboarding (first run)
  onboarding_title: 'Bienvenue à Canadian Scam Shield',
  onboarding_welcome: 'Vous êtes protégé. Voici ce que cela veut dire.',
  onboarding_intro:
    'Canadian Scam Shield surveille discrètement les fraudes qui se font passer '
    + 'pour des organismes canadiens comme l’ARC, votre banque ou Postes Canada. '
    + 'Il travaille en arrière-plan — il ne vous parle que lorsqu’une chose '
    + 'semble louche.',
  onboarding_layer1_title: 'Faux sites Web',
  onboarding_layer1: 'Il vous avertit des faux sites canadiens et des sites imitateurs avant que vous leur fassiez confiance.',
  onboarding_layer2_title: 'Pages frauduleuses',
  onboarding_layer2: 'Il vérifie la page où vous êtes pour repérer les astuces des fraudeurs, comme les fausses demandes de remboursement ou de paiement.',
  onboarding_layer3_title: 'Courriels et textos suspects',
  onboarding_layer3: 'Collez un courriel ou un texto dans la fenêtre pour le vérifier — ou laissez l’outil vérifier les courriels que vous ouvrez dans Gmail et Outlook.',
  onboarding_privacy_title: 'Votre vie privée',
  onboarding_privacy:
    'Tout est vérifié ici, sur votre appareil. Votre navigation et vos courriels '
    + 'ne nous sont jamais envoyés, ni à personne d’autre.',
  onboarding_choose_language: 'Choisissez votre langue',
  onboarding_done: 'Commencer',
  onboarding_open_settings: 'Ouvrir les paramètres',

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
