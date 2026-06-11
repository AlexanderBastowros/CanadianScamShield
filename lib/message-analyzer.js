/**
 * lib/message-analyzer.js
 * Layer 3 — email/SMS paste-checker engine for Canadian Scam Shield.
 *
 * A rule interpreter over data/scam-sender-patterns.json (39 weighted rules).
 * Pure ES module — no DOM, no Chrome APIs — so it runs in the MV3 service
 * worker and in Node tests alike.
 *
 *   analyzeMessage(rawText, { patterns, senderDomains, whitelist, headers, isPro, lang })
 *     → { score, verdict, firedRules, extractedLinks, senderDomain, officialContact }
 *
 * Rule semantics: a rule fires when ALL predicates in its `match` object hold
 * (ANDed), with one documented exception: `or_password_protected_archive`
 * widens `attachment_extension_in` into an OR pair. Predicates we cannot
 * evaluate (missing data, unimplemented heuristic) evaluate to FALSE so the
 * rule simply does not fire — fail safe, never fail open.
 */

import { isDomainLookalike } from './homoglyph.js';

// ---------------------------------------------------------------------------
// Generic text helpers
// ---------------------------------------------------------------------------

/** Escapes regex metacharacters; internal whitespace becomes \s+. */
function escapeRegex(str) {
  return str
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\ /g, '\\s+')
    .replace(/\s+/g, '\\s+');
}

/**
 * Word-ish boundary matcher (same model as content-analyzer):
 * preceded/followed by start/end or a non-alphanumeric character. Avoids \b
 * so terms containing '/', spaces, hyphens, or accented French still work.
 */
function termMatches(haystack, term) {
  if (!term) return false;
  const re = new RegExp(
    '(^|[^a-z0-9])' + escapeRegex(String(term).toLowerCase()) + '([^a-z0-9]|$)',
    'i'
  );
  return re.test(haystack);
}

/** True if any term in `terms` matches `haystack` (pre-lowercased). */
function anyTermMatches(haystack, terms) {
  return Array.isArray(terms) && terms.some((t) => termMatches(haystack, t));
}

/** Suffix-match: host equals entry or ends with '.'+entry. */
function hostMatches(host, entry) {
  return host === entry || host.endsWith('.' + entry);
}

/** True if `host` suffix-matches any domain in the whitelist set. */
function hostInWhitelist(host, whitelistDomains) {
  if (!host) return false;
  let candidate = host;
  while (candidate) {
    if (whitelistDomains.has(candidate)) return true;
    const dot = candidate.indexOf('.');
    if (dot === -1) break;
    candidate = candidate.slice(dot + 1);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Exported extraction helpers
// ---------------------------------------------------------------------------

/** Extracts all http(s) URLs from free text. */
export function extractLinks(text) {
  return (String(text).match(/https?:\/\/[^\s<>"')\]]+/gi) || []);
}

/** Extracts North-American style phone numbers (1-800-555-0199, (416) 555-0199…). */
export function extractPhoneNumbers(text) {
  const re = /(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}/g;
  return String(text).match(re) || [];
}

/**
 * Parses a From line: `Display Name <user@host>` or a bare address.
 * @returns {{displayName:string, email:string|null, domain:string|null}}
 */
export function parseSenderLine(fromString) {
  const s = String(fromString || '').trim();
  const angled = s.match(/^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>$/);
  let displayName = '';
  let email = null;
  if (angled) {
    displayName = angled[1].trim().replace(/^["']|["']$/g, '');
    email = angled[2].trim();
  } else {
    const bare = s.match(/[^\s"'<>]+@[^\s"'<>]+/);
    if (bare) {
      email = bare[0];
      displayName = s.replace(bare[0], '').trim().replace(/^["']|["']$/g, '');
    } else {
      displayName = s;
    }
  }
  const domain = email ? email.split('@')[1]?.toLowerCase() ?? null : null;
  return { displayName, email, domain };
}

// ---------------------------------------------------------------------------
// Internal: extract context once per call
// ---------------------------------------------------------------------------

const FREE_PROVIDERS = [
  'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'yahoo.ca',
  'live.com', 'live.ca', 'icloud.com', 'proton.me', 'protonmail.com',
  'aol.com', 'mail.com', 'gmx.com', 'zoho.com', 'yandex.com',
];

function hostOfUrl(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

/** Builds the evaluation context shared by all predicates. */
function buildContext(rawText, opts) {
  const { patterns, senderDomains, whitelist, headers, isPro } = opts;

  const body = String(rawText || '');
  const bodyLower = body.toLowerCase();

  // Sender: explicit headers win; otherwise look for a leading "From:" line.
  let from = headers?.from || null;
  if (!from) {
    const m = body.match(/^from:\s*(.+)$/im);
    if (m) from = m[1];
  }
  const sender = parseSenderLine(from || '');

  const replyTo = headers?.replyTo ? parseSenderLine(headers.replyTo) : null;
  const subject = String(headers?.subject || '');

  const links = extractLinks(body);
  const linkHosts = links.map(hostOfUrl).filter(Boolean);

  // HTML anchors (for text/href mismatch checks on pasted HTML email source)
  const anchors = [];
  const anchorRe = /<a[^>]*href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi;
  let am;
  while ((am = anchorRe.exec(body)) !== null) {
    anchors.push({ href: am[1], text: am[2].trim() });
  }

  const whitelistDomains = new Set(
    (whitelist?.institutions || []).map((i) => i.domain.toLowerCase())
  );
  const highValueEntries = (whitelist?.institutions || []).filter((i) => i.high_value);
  const orgs = senderDomains?.organizations || [];

  // All candidate hosts a spoofing check should look at
  const allHosts = [sender.domain, ...linkHosts].filter(Boolean);

  return {
    body, bodyLower, sender, replyTo, subject,
    links, linkHosts, anchors, allHosts,
    whitelistDomains, highValueEntries, orgs,
    patterns, isPro,
    authResults: String(headers?.authResults || ''),
    firedCount: 0, // updated as rules fire (for other_rules_triggered_count_gte)
  };
}

// ---------------------------------------------------------------------------
// Predicate evaluators — each returns boolean; unknown data ⇒ false
// ---------------------------------------------------------------------------

const PREDICATES = {

  // ── Sender-domain predicates ────────────────────────────────────────────
  from_domain_in: (ctx, list) =>
    !!ctx.sender.domain && list.includes(ctx.sender.domain),

  from_domain_contains_any: (ctx, list) =>
    !!ctx.sender.domain && list.some((s) => ctx.sender.domain.includes(s)),

  from_domain_starts_with: (ctx, prefix) =>
    !!ctx.sender.domain && ctx.sender.domain.startsWith(prefix),

  from_domain_tld_in: (ctx, list) =>
    !!ctx.sender.domain && list.some((tld) => ctx.sender.domain.endsWith(tld)),

  from_domain_not_ends_with: (ctx, list) =>
    !!ctx.sender.domain && !list.some((sfx) => ctx.sender.domain.endsWith(sfx)),

  from_domain_in_whitelist: (ctx) =>
    hostInWhitelist(ctx.sender.domain, ctx.whitelistDomains),

  from_domain_not_in_whitelist: (ctx) =>
    !!ctx.sender.domain && !hostInWhitelist(ctx.sender.domain, ctx.whitelistDomains),

  from_domain_not_in_known_sender_domains_for: (ctx, orgIds) => {
    if (!ctx.sender.domain) return false;
    const byId = new Map(ctx.orgs.map((o) => [o.id, o]));
    return orgIds.every((id) => {
      const org = byId.get(id);
      if (!org) return true;
      return !(org.sending_domains || []).some((d) => hostMatches(ctx.sender.domain, d));
    });
  },

  reply_to_domain_in: (ctx, list) =>
    !!ctx.replyTo?.domain && list.includes(ctx.replyTo.domain),

  // ── Body / display-name text predicates ─────────────────────────────────
  body_contains_any: (ctx, terms) => anyTermMatches(ctx.bodyLower, terms),

  body_contains_any_secondary: (ctx, terms) => anyTermMatches(ctx.bodyLower, terms),

  subject_or_body_contains_any: (ctx, terms) =>
    anyTermMatches((ctx.subject + '\n' + ctx.body).toLowerCase(), terms),

  body_or_display_contains_any: (ctx, terms) =>
    anyTermMatches((ctx.sender.displayName + '\n' + ctx.body).toLowerCase(), terms),

  body_or_display_claims_institution: (ctx) => {
    const hay = (ctx.sender.displayName + '\n' + ctx.body).toLowerCase();
    return ctx.orgs.some((org) => anyTermMatches(hay, org.aliases || []));
  },

  /** Array of OR-groups; every group needs at least one matching term. */
  body_contains_all_of: (ctx, groups) =>
    Array.isArray(groups) &&
    groups.every((group) => anyTermMatches(ctx.bodyLower, group)),

  body_contains_phone_number: (ctx) => extractPhoneNumbers(ctx.body).length > 0,

  body_contains_sin_pattern: (ctx) =>
    /\b\d{3}[- ]?\d{3}[- ]?\d{3}\b/.test(ctx.body),

  body_dollar_amount_in_range: (ctx, [min, max]) => {
    const amounts = [...ctx.body.matchAll(/\$\s?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)/g)]
      .map((m) => parseFloat(m[1].replace(/,/g, '')));
    return amounts.some((a) => a >= min && a <= max);
  },

  /** AI-polish heuristic intentionally not implemented — never matches. */
  body_appears_ai_polished: () => false,

  // ── Link predicates ──────────────────────────────────────────────────────
  link_present: (ctx) => ctx.links.length > 0,

  link_domain_not_in_whitelist: (ctx) =>
    ctx.linkHosts.some((h) => !hostInWhitelist(h, ctx.whitelistDomains)),

  link_domains_contain_any: (ctx, list) =>
    ctx.linkHosts.some((h) => list.some((d) => hostMatches(h, d))),

  link_url_is_ip_address: (ctx) =>
    ctx.linkHosts.some((h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h)),

  link_text_domain_differs_from_href_domain: (ctx) =>
    ctx.anchors.some((a) => {
      const hrefHost = hostOfUrl(a.href);
      const textHost = hostOfUrl(a.text) || (a.text.match(/^[a-z0-9.-]+\.[a-z]{2,}$/i) ? a.text.toLowerCase() : null);
      return !!hrefHost && !!textHost && hrefHost !== textHost.replace(/^www\./, '');
    }),

  link_text_in_whitelist: (ctx) =>
    ctx.anchors.some((a) => {
      const textHost = hostOfUrl(a.text) || (a.text.match(/^[a-z0-9.-]+\.[a-z]{2,}$/i) ? a.text.toLowerCase() : null);
      return !!textHost && hostInWhitelist(textHost.replace(/^www\./, ''), ctx.whitelistDomains);
    }),

  registrable_domain_not_in_whitelist: (ctx) =>
    ctx.allHosts.some((h) => !hostInWhitelist(h, ctx.whitelistDomains)),

  subdomain_contains_institution_name: (ctx) =>
    ctx.allHosts.some((h) =>
      [...ctx.whitelistDomains].some(
        (wd) => h.includes(wd) && !hostMatches(h, wd)
      )
    ),

  lookalike_of_high_value_whitelist: (ctx) =>
    ctx.allHosts.some((h) =>
      // A host that is ITSELF whitelisted can never be a "lookalike" — e.g.
      // amazon.ca is within edit distance 2 of amazon.com, but both are real.
      !hostInWhitelist(h, ctx.whitelistDomains) &&
      ctx.highValueEntries.some(
        (e) => h !== e.domain && isDomainLookalike(h, e.domain, 2)
      )
    ),

  // ── Misc predicates ──────────────────────────────────────────────────────
  attachment_extension_in: (ctx, exts) => {
    const escaped = exts.map((e) => e.replace('.', '\\.')).join('|');
    return new RegExp(`\\S(${escaped})([^a-z0-9]|$)`, 'i').test(ctx.body);
  },

  /** Evaluated standalone only as part of the OR special-case (see below). */
  or_password_protected_archive: (ctx) =>
    /password[- ]?protected\s+(zip|archive|rar|file)/i.test(ctx.body),

  email_body_contains_html_form: (ctx) => /<form\b/i.test(ctx.body),

  target_email_on_free_provider: (ctx) => {
    const emails = ctx.body.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
    return emails.some((e) => {
      const dom = e.split('@')[1].toLowerCase();
      return FREE_PROVIDERS.includes(dom) && e !== ctx.sender.email;
    });
  },

  /** [Pro] Parses pre-extracted auth results (e.g. "spf=fail dkim=pass"). */
  spf_or_dkim_or_dmarc_failed: (ctx) =>
    ctx.isPro === true &&
    /(spf|dkim|dmarc)\s*=\s*fail/i.test(ctx.authResults),

  claimed_brand_in_whitelist: (ctx) => {
    const hay = (ctx.sender.displayName + '\n' + ctx.body).toLowerCase();
    const aliasHit = ctx.orgs.some((org) => anyTermMatches(hay, org.aliases || []));
    if (aliasHit) return true;
    return (ctx.patterns ? [] : []).length > 0 ||
      [...ctx.whitelistDomains].some((d) => termMatches(hay, d));
  },

  /** Evaluated in a second pass against the count of already-fired rules. */
  other_rules_triggered_count_gte: (ctx, n) => ctx.firedCount >= n,
};

/**
 * Evaluates one rule's match object against the context.
 * Special case: `or_password_protected_archive` is OR-combined with
 * `attachment_extension_in` (the data models them as an OR pair).
 */
function ruleFires(rule, ctx) {
  const match = rule.match || {};
  const keys = Object.keys(match);

  // Special-case the OR pair
  if (keys.includes('or_password_protected_archive')) {
    const extOk = keys.includes('attachment_extension_in')
      ? PREDICATES.attachment_extension_in(ctx, match.attachment_extension_in)
      : false;
    const pwOk = PREDICATES.or_password_protected_archive(ctx);
    if (!extOk && !pwOk) return false;
    // Remaining predicates (if any) are still ANDed
    return keys
      .filter((k) => k !== 'attachment_extension_in' && k !== 'or_password_protected_archive')
      .every((k) => PREDICATES[k] ? PREDICATES[k](ctx, match[k]) : false);
  }

  return keys.every((k) => (PREDICATES[k] ? PREDICATES[k](ctx, match[k]) : false));
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * analyzeMessage(rawText, options)
 *
 * @param {string} rawText - the pasted message (plain text or HTML source)
 * @param {object} [options]
 * @param {object} [options.patterns]      - parsed scam-sender-patterns.json
 * @param {object} [options.senderDomains] - parsed known-sender-domains.json
 * @param {object} [options.whitelist]     - parsed whitelist.json
 * @param {object} [options.headers]       - { from, replyTo, subject, authResults }
 * @param {boolean} [options.isPro]        - enables auth-header analysis
 * @param {string} [options.lang]          - 'en' | 'fr' (explanation language)
 *
 * @returns {{
 *   score: number, verdict: 'safe'|'low'|'medium'|'high',
 *   firedRules: Array<{id:string, weight:number, explanation:string}>,
 *   extractedLinks: string[], senderDomain: string|null,
 *   officialContact: {name:string, url:string|null, phone:string|null}|null
 * }}
 */
export function analyzeMessage(rawText, options = {}) {
  const {
    patterns      = { rules: [] },
    senderDomains = { organizations: [] },
    whitelist     = { institutions: [] },
    headers       = null,
    isPro         = false,
    lang          = 'en',
  } = options;

  const ctx = buildContext(rawText, { patterns, senderDomains, whitelist, headers, isPro });

  // ── Verified-sender dampening ────────────────────────────────────────────
  // If the address after the @ suffix-matches a whitelisted institution domain
  // or a known organization sending domain (e.g. email@amazon.ca,
  // notify@payments.interac.ca), the sender is at least CLAIMING a legitimate
  // domain. Legitimate mail from these senders routinely mentions gift cards,
  // packages, transfers, deadlines, etc., so content-keyword rules generate
  // false positives — the #1 trust killer. For verified senders we therefore
  // only keep structural rules that indicate spoofing or payload danger
  // regardless of who sent it (bad attachments, failed authentication,
  // reply-to hijacks, link text/href mismatches, IP links, embedded forms).
  //
  // Caveat: a From header is spoofable, so this is dampening, not proof —
  // truly forged mail is still caught by auth_failure_known_brand (Pro) and
  // the structural rules, and webmail providers reject most hard forgeries
  // of these domains via SPF/DKIM/DMARC before the user ever sees them.
  const senderVerified =
    !!ctx.sender.domain &&
    (hostInWhitelist(ctx.sender.domain, ctx.whitelistDomains) ||
      ctx.orgs.some((org) =>
        (org.sending_domains || []).some((d) => hostMatches(ctx.sender.domain, d))
      ));

  const STRUCTURAL_KEYS = [
    'attachment_extension_in',
    'or_password_protected_archive',
    'spf_or_dkim_or_dmarc_failed',
    'reply_to_domain_in',
    'link_text_domain_differs_from_href_domain',
    'link_url_is_ip_address',
    'email_body_contains_html_form',
  ];
  const isStructuralRule = (rule) =>
    Object.keys(rule.match || {}).some((k) => STRUCTURAL_KEYS.includes(k));

  const firedRules = [];
  let score = 0;

  const rules = Array.isArray(patterns.rules) ? patterns.rules : [];

  // Two passes: rules depending on other rules' firing count go last.
  const dependent = rules.filter((r) => r.match && 'other_rules_triggered_count_gte' in r.match);
  const independent = rules.filter((r) => !dependent.includes(r));

  for (const rule of [...independent, ...dependent]) {
    // Verified sender: skip content-keyword rules; keep structural ones.
    if (senderVerified && !isStructuralRule(rule)) continue;

    let fires = false;
    try {
      fires = ruleFires(rule, ctx);
    } catch {
      fires = false; // a malformed rule must never break the analysis
    }
    if (fires) {
      const explanation =
        (lang === 'fr' && rule.user_explanation_fr) ||
        rule.user_explanation ||
        rule.id;
      firedRules.push({ id: rule.id, weight: rule.weight, explanation });
      score += rule.weight || 0;
      ctx.firedCount = firedRules.length;
    }
  }

  score = Math.min(100, score);
  const verdict =
    score >= 80 ? 'high' :
    score >= 55 ? 'medium' :
    score >= 30 ? 'low' : 'safe';

  // Official contact: first org whose alias appears in the display name or body
  let officialContact = null;
  const hay = (ctx.sender.displayName + '\n' + ctx.body).toLowerCase();
  for (const org of ctx.orgs) {
    if (anyTermMatches(hay, org.aliases || [])) {
      officialContact = {
        name: org.name || org.id,
        url: org.official_contact_url || null,
        phone: org.official_phone || null,
      };
      break;
    }
  }

  return {
    score,
    verdict,
    firedRules,
    extractedLinks: ctx.links,
    senderDomain: ctx.sender.domain,
    senderVerified,
    officialContact,
  };
}
