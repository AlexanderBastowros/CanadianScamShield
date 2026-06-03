# claudecmds.md — Canadian Scam Shield / Phase 1 Chrome Extension

Paste any of these prompts directly into Claude Code to pick up a specific task.
Each prompt is self-contained with enough context to not require re-explaining the project.

---

## 0. ORIENTATION (run this first in a new Claude Code session)

```
Read handoff.md in full before doing anything else. Then list the current contents
of the project directory so I can see what files already exist vs what still needs
to be created.
```

---

## 1. MANIFEST + EXTENSION SKELETON

```
You are building a Chrome Extension called "Canadian Scam Shield" using Manifest V3.

Read handoff.md for full context. Then create the following files:

1. manifest.json — MV3 config with:
   - name: "Canadian Scam Shield"
   - version: "0.1.0"
   - description: "Protects Canadians from scam websites, emails, and texts."
   - Permissions: storage, alarms, declarativeNetRequest, tabs, activeTab, scripting
   - Host permissions: <all_urls>
   - background: service_worker pointing to background/service-worker.js
   - Content script: content/content-script.js injected at document_idle on all URLs
   - CSS: content/overlay.css
   - Action popup: popup/popup.html
   - Options page: options/options.html
   - Icons: icons/icon16.png, icon48.png, icon128.png (stub with placeholder references for now)
   - web_accessible_resources: warning/warning.html

2. background/service-worker.js — Stub with:
   - chrome.runtime.onInstalled handler (log "Canadian Scam Shield installed")
   - chrome.tabs.onUpdated listener that fires URL analysis when status === 'complete'
   - chrome.runtime.onMessage handler (router for future message types)
   - Import stubs for url-analyzer.js (use importScripts or ES module import)

3. content/content-script.js — Stub with:
   - DOMContentLoaded listener
   - chrome.runtime.sendMessage({ type: 'PAGE_LOAD', url: window.location.href })
   - Placeholder function injectBanner(message, level) that creates a fixed banner div

4. content/overlay.css — Minimal stub with:
   - .css-scam-banner base styles (fixed top, z-index 999999, hidden by default)
   - .css-scam-banner--low (blue)
   - .css-scam-banner--medium (yellow/amber)
   - .css-scam-banner--high (red)

5. popup/popup.html — Minimal stub with a status area and a "Check a message" tab

6. warning/warning.html — Full-page warning stub with placeholder text

Use the exact file structure from handoff.md. Do not use inline scripts in any HTML file
(MV3 CSP). All JS must be in separate .js files.
```

---

## 2. URL ANALYZER (Layer 1)

```
You are building lib/url-analyzer.js for the Canadian Scam Shield Chrome extension.
Read handoff.md for full architecture context.

The URL analyzer is Layer 1 detection — runs on every navigation in ~5ms.

Implement analyzeUrl(url) that returns:
{
  verdict: 'safe' | 'low' | 'medium' | 'high',
  score: number,          // 0–100
  reasons: string[],      // human-readable trigger list
  officialUrl: string | null,   // from whitelist if known
  institutionName: string | null
}

Detection steps (in order):
1. Parse URL → extract apex domain (strip www., subdomains)
2. Normalize to lowercase
3. Exact match against data/whitelist.json → return { verdict: 'safe' } immediately
4. Exact match against data/known-bad.json → return { verdict: 'high' }
5. Run homoglyph normalization (import from lib/homoglyph.js) then Levenshtein ≤ 2
   against all high_value: true entries in whitelist.json → if hit, add score +60
6. TLD enforcement: if domain contains any of
   ['cra', 'canada-revenue', 'revenue-canada', 'arc-canada', 'service-canada',
    'servicecanada', 'ircc', 'rcmp', 'canada-post']
   AND does NOT end in .gc.ca or .canada.ca → add score +50, reason: "Fake government domain"
7. Suspicious TLD: if domain ends in any of
   ['.xyz', '.top', '.click', '.live', '.vip', '.online', '.site', '.info',
    '.biz', '.tk', '.ml', '.ga', '.cf', '.gq'] → add score +30
8. Excessive hyphens: if domain (excluding TLD) has ≥ 3 hyphens → add score +20
9. IP in URL: if hostname matches IPv4 pattern → add score +40
10. Punycode: if hostname contains 'xn--' → add score +40
11. Suspicious subdomain chain: if the registrable domain (eTLD+1) is NOT in whitelist
    but a subdomain segment exactly matches a whitelisted domain → add score +45,
    reason: "Subdomain spoofing — reads as real but domain is different"
12. Cap score at 100. Map to verdict:
    - score < 30 → 'safe'  (but only if not whitelisted — we already returned safe above)
    - 30–54 → 'low'
    - 55–79 → 'medium'
    - ≥ 80 → 'high'

The data files (whitelist.json, known-bad.json) should be loaded once and cached.
The function must be usable in a MV3 service worker context (no DOM APIs).
Write clean, well-commented ES module code.
```

---

## 3. HOMOGLYPH NORMALIZER

```
You are building lib/homoglyph.js for the Canadian Scam Shield Chrome extension.
Read handoff.md for context.

Implement:
1. normalizeHomoglyphs(str) — replaces common Unicode lookalikes with their ASCII equivalent.
   At minimum, cover:
   - Cyrillic: а→a, е→e, о→o, р→p, с→c, х→x, у→y, і→i
   - Greek: α→a, ο→o, ε→e, ν→v
   - Visually similar: ℓ→l, ı→i, 0→o (contextual, only in domain context)
   - Full-width Latin: Ａ→A, etc. (U+FF01–U+FF5E range)

2. levenshtein(a, b) — standard Levenshtein distance, works on short strings (domains).
   Return the edit distance as an integer.

3. isDomainLookalike(inputDomain, candidateDomain, maxDistance = 2) — returns boolean.
   Normalize both strings first, then compute Levenshtein.

Export all three functions. MV3 service worker compatible (no DOM).
```

---

## 4. MESSAGE ANALYZER (Layer 3)

```
You are building lib/message-analyzer.js for the Canadian Scam Shield Chrome extension.
Read handoff.md for full context, especially the scam-sender-patterns.json schema section.

Implement analyzeMessage(rawText, options = {}) that:

Input: rawText is a string pasted by the user (email body, SMS, etc.)
       options.headers: optional parsed email headers object { from, replyTo, subject, authResults }
       options.isPro: boolean (enables auth header analysis)

Returns:
{
  score: number,           // 0–100
  verdict: 'safe' | 'low' | 'medium' | 'high',
  firedRules: [
    {
      id: string,           // rule id from scam-sender-patterns.json
      weight: number,
      explanation: string   // user_explanation from the rule
    }
  ],
  extractedLinks: string[],
  senderDomain: string | null,
  officialContact: { url: string, phone: string } | null  // from known-sender-domains.json if matched
}

Core detection logic to implement:

1. Extract sender domain from headers.from if present
2. Check if display name (before <>) matches any alias in known-sender-domains.json
   If display name matches org X but sender domain is NOT in org X's sending_domains → fire display_name_domain_mismatch
3. Check if sender domain is a free provider (gmail, outlook, hotmail, yahoo, live, icloud, proton, etc.)
   Cross-reference body + display name for institutional claims → fire matching free_provider_claiming_institution rules
4. Extract all URLs from rawText (regex: https?://[^\s<>"]+)
5. Check URLs against whitelist.json
6. Detect shortened URLs (bit.ly, tinyurl.com, goo.gl, t.co, rb.gy, etc.) → fire shortened_link_institutional if body claims institution
7. Detect IP-address URLs → fire ip_address_link
8. Detect link text vs href mismatch (if HTML email with <a> tags)
9. Scan body for each rule's body_contains_any patterns:
   - gift card keywords → gift_card_payment_request
   - crypto keywords → crypto_payment_request
   - SIN request keywords → sin_request
   - arrest/warrant language → urgency_arrest_warrant
   - 24-hour deadline language → urgency_24_hours
   - password request → credential_request_password
   - OTP request → credential_request_otp
   - iMessage Y-reply trick → imessage_evasion_reply_y
   - Toll road patterns (407, A25, etc.) → toll_road_unpaid_link
   - Licence revocation threat → license_revocation_threat
   - Package redelivery fee → canada_post_redelivery_fee
   - Geek Squad invoice template → geek_squad_exact_template (composite: subject + body + phone number + dollar amount)
   - e-Transfer loading screen → etransfer_loading_screen
   - Alberta rebate scam → alberta_rebate_text_scam
   - A25 bridge scam → a25_toll_bridge_scam
   - CRA refund e-Transfer → tax_refund_etransfer_lure
   - Account security alert → fake_security_alert_2fa
10. [Pro only] If headers.authResults present, parse SPF/DKIM/DMARC result → fire auth_failure_known_brand if failed + claimed brand in whitelist
11. Accumulate weights, cap at 100, map to verdict using same thresholds as url-analyzer.js

Load scam-sender-patterns.json and known-sender-domains.json once and cache.
Use ES module syntax. MV3 compatible.
Include a helper extractPhoneNumbers(text) since several rules check for phone numbers in body.
```

---

## 5. CONTENT ANALYZER (Layer 2)

```
You are building lib/content-analyzer.js for the Canadian Scam Shield Chrome extension.
Read handoff.md for context.

This module runs inside content-script.js (has DOM access).

Implement analyzePageContent() → returns the same verdict shape as url-analyzer.js.

Steps:
1. Extract visible text: document.body.innerText (strip script/style/noscript content first)
2. Extract page title: document.title
3. Extract meta description: document.querySelector('meta[name="description"]')?.content
4. Extract form field labels and input names/placeholders
5. Score against scam keyword categories:

   Impersonation terms (weight 15 each, max 45):
   - "CRA", "Canada Revenue Agency", "Revenue Canada"
   - "Service Canada", "IRCC", "Immigration Canada"
   - "GST/HST refund", "tax refund", "refund available"
   - "Service Ontario", "ServiceOntario"

   Urgency triggers (weight 20 each, max 40):
   - "warrant", "arrest", "criminal charges"
   - "account suspended", "suspended immediately"
   - "within 24 hours", "immediate action required"
   - "final notice", "final warning"

   Payment red flags (weight 30 each, max 60):
   - "gift card", "iTunes card", "Google Play card"
   - "Bitcoin", "cryptocurrency", "crypto wallet"
   - "wire transfer", "Western Union", "MoneyGram"

   Credential harvesting (weight 25 each):
   - SIN input field (input with name/id/placeholder containing "sin", "social insurance", "NAS")
     on a non-.gc.ca / non-.canada.ca domain
   - Password field on non-HTTPS
   - Credit card CVV field outside of a payment processor domain

6. If current domain is in whitelist.json → return { verdict: 'safe' } early (Layer 1 should have caught this,
   but content script is a safety net)
7. Combine scores, cap at 100, apply verdict thresholds

Export analyzePageContent() as default export.
Note: this file runs in the content script context, so it CAN use document/window.
It still cannot use chrome.storage directly from here — pass results back via chrome.runtime.sendMessage.
```

---

## 6. WARNING PAGE (Full-Page Block)

```
You are building warning/warning.html and warning/warning.js for the Canadian Scam Shield
Chrome extension. Read handoff.md for UX and legal context.

Design constraints:
- No inline scripts (MV3 CSP)
- Must look trustworthy and calm — NOT alarming red sirens. Think: clear, official, helpful.
- Must be accessible: large fonts (≥18px body), high contrast, keyboard navigable
- Bilingual: show EN by default, with a toggle to FR

The warning page receives its data via URL query params:
  ?url=<encoded-suspicious-url>
  &score=<0-100>
  &reasons=<JSON-encoded array of reason strings>
  &officialUrl=<encoded real site URL if known>
  &institutionName=<encoded name if known>
  &lang=en|fr

Content to display:
1. Extension name + maple leaf icon (CSS-drawn, no external image)
2. Heading: "This site may be trying to scam you" (EN) / "Ce site tente peut-être de vous escroquer" (FR)
3. The suspicious URL (truncated if too long)
4. Why we flagged it: bullet list from reasons[]
5. If officialUrl known: "Looking for [institutionName]? The real site is:" + a link to officialUrl
6. CAFC reporting info: "Report this scam to the Canadian Anti-Fraud Centre: 1-888-495-8501"
7. Two buttons:
   - "Go back to safety" (primary, goes to chrome://newtab or history.back())
   - "I understand the risk, proceed anyway" (secondary, small, opens the original URL)

The "proceed anyway" click should send a message to the service worker logging the override
(for future analytics, no PII).

Style it well — this is the most important UI surface. It should feel like a trusted Canadian
government advisory notice: clean, bilingual, reassuring in tone, authoritative without being scary.
```

---

## 7. POPUP UI

```
You are building popup/popup.html, popup/popup.js, and popup/popup.css for the
Canadian Scam Shield Chrome extension. Read handoff.md for context.

The popup has two tabs:
1. "Status" tab — shows the safety state of the current active tab
2. "Check a message" tab — the email/SMS paste checker

Tab 1 — Status:
- Query the service worker for the current tab's analysis result
- Display one of three states:
  a. ✅ Site looks safe — show green indicator + site name from whitelist if matched
  b. ⚠️ Caution — show amber indicator + top reason (medium confidence)
  c. 🚫 Flagged as suspicious — show red indicator + top reasons + link to warning page
- Small "Why?" link that expands reasons accordion
- Link to options page
- CAFC logo/link (text only)

Tab 2 — Check a message:
- Textarea: "Paste an email or text message here" (EN) / equivalent FR
- Optional: sender field (From address if available)
- "Check it" button → calls message-analyzer.js via service worker
- Results panel (hidden until check runs):
  - Score meter (visual 0–100 bar)
  - Verdict badge
  - Fired rules list with plain-language explanations
  - Recommended action text

Design: 380px wide (Chrome popup max), clean, accessible, bilingual toggle in header.
Maple leaf motif in the header. No external fonts (use system-ui or bundled font).
No inline scripts. All logic in popup.js.
```

---

## 8. OPTIONS PAGE

```
You are building options/options.html and options/options.js for the Canadian Scam Shield
Chrome extension. Read handoff.md for full feature context including the Free vs Pro tiers.

Settings to implement:

[FREE TIER]
- Language: English | Français (radio buttons, saves to chrome.storage.sync)
- Whitelist management: list user's personal trusted sites + add/remove UI
  (saves to chrome.storage.sync as customWhitelist: string[])

[PRO TIER — show with lock icon + "Shield Pro" badge if not subscribed]
- Sensitivity: Strict | Balanced | Permissive
  (shifts threshold ±15, saves to chrome.storage.sync as sensitivity: 'strict'|'balanced'|'permissive')
- Custom blocklist: list + add/remove UI
  (saves to chrome.storage.sync as customBlocklist: string[])
- External threat APIs: toggle for PhishTank opt-in
  (shows a note: "Suspicious URLs will be checked against PhishTank's database")

[INFO SECTION]
- Version number (pull from manifest.json)
- Data last updated timestamp (from chrome.storage.local.dataLastUpdated)
- Link to CAFC
- "Report a false positive" link (opens GitHub issues page or email)
- Privacy policy summary (one paragraph, no external data sent in free tier)

Pro upgrade prompt: clicking any Pro-gated feature shows a small modal/callout:
"Upgrade to Shield Pro ($3.99/month) to unlock this feature" + link to payment page (placeholder URL for now)

Save all settings with immediate chrome.storage.sync.set(). Show a "Saved ✓" confirmation.
```

---

## 9. DATA UPDATE SERVICE (Background Worker)

```
You are adding a data update system to background/service-worker.js for the
Canadian Scam Shield Chrome extension. Read handoff.md for the data strategy section.

Add to the service worker:

1. On chrome.alarms.onAlarm, if alarm.name === 'dailyDataUpdate', call fetchDataUpdates()

2. On chrome.runtime.onInstalled, schedule the alarm:
   chrome.alarms.create('dailyDataUpdate', { periodInMinutes: 1440 })

3. fetchDataUpdates() should:
   - Fetch from these URLs (placeholder — will be real GitHub raw URLs):
     const DATA_BASE_URL = 'https://raw.githubusercontent.com/[ORG]/canadian-scam-shield-data/main/'
     files: ['whitelist.json', 'scam-sender-patterns.json', 'known-sender-domains.json', 'known-bad.json']
   - For each file: compare version field to cached version in chrome.storage.local
   - If newer: store updated content in chrome.storage.local under the filename as key
   - Update chrome.storage.local.dataLastUpdated = new Date().toISOString()
   - If fetch fails: log error, do NOT clear existing data (fail closed)

4. getDataFile(filename) — helper that returns parsed JSON from chrome.storage.local,
   falling back to the bundled version (imported at top of service worker) if local storage
   has nothing yet.

The data files are the source of truth for all analysis modules. All three analyzers should
call getDataFile() rather than importing directly, so they benefit from live updates.
```

---

## 10. KNOWN-BAD SEED FILE

```
You are creating data/known-bad.json for the Canadian Scam Shield Chrome extension.
Read handoff.md for context.

Create the file with this schema:
{
  "version": "1.0.0",
  "last_updated": "2026-05-27",
  "description": "Confirmed malicious domains blocked immediately on navigation. Sources: CAFC bulletins, PhishTank Canadian entries, community reports.",
  "domains": []
}

Leave the domains array empty for now — we'll populate it from CAFC and PhishTank data.
Add a comment block at the top of the file explaining the format:
- Each entry in domains[] is a string: the apex domain only (no protocol, no www., no path)
- Subdomains of listed domains are also blocked
- This file is updated daily from the GitHub data repo

Also create data/scam-keywords.json as a standalone extraction of the keyword categories
currently embedded in scam-sender-patterns.json, for use by the content-analyzer Layer 2:

{
  "version": "1.0.0",
  "categories": {
    "impersonation_terms": { "weight": 15, "terms": [...] },
    "urgency_triggers": { "weight": 20, "terms": [...] },
    "payment_red_flags": { "weight": 30, "terms": [...] },
    "credential_harvesting": { "weight": 25, "terms": [...] }
  }
}

Populate each category's terms array from the relevant rule matches already in
scam-sender-patterns.json — no new invention, just extraction and organization.
```

---

## 11. BILINGUAL STRING SYSTEM

```
You are adding bilingual (EN/FR) support to the Canadian Scam Shield Chrome extension.
Read handoff.md for context.

1. Create lib/i18n.js with:
   - A strings object containing all user-facing strings in both languages
   - getStrings(lang) → returns the string set for 'en' or 'fr'
   - t(key, lang) → returns translated string, falls back to 'en'
   - detectLanguage() → checks chrome.storage.sync for user pref, then navigator.language, defaults to 'en'

2. All UI files (popup.html, warning.html, options.html) should reference string keys,
   and popup.js / warning.js / options.js should call t() to populate them on load.

3. Add French translations for all user_explanation strings in scam-sender-patterns.json.
   Add a "user_explanation_fr" field alongside each existing "user_explanation" field.
   Translate accurately — these are the plain-language explanations users read when flagged.
   Focus on clarity over formality. Target reading level: Grade 8.

4. Add French translations for:
   - Warning page headings and body copy
   - Popup tab labels and status messages
   - Options page labels
   - All CAFC references (they are bilingual: antifraudcentre-centreantifraude.ca)
```

---

## 12. INTEGRATION TEST SUITE

```
You are writing integration tests for the Canadian Scam Shield Chrome extension.
Read handoff.md for the detection architecture.

Use Jest (or Vitest if preferred). Tests should run in Node — no browser required for unit tests.

Write tests for:

lib/homoglyph.js:
- normalizeHomoglyphs: Cyrillic а → a, Greek ο → o, full-width Ａ → A
- levenshtein: known distances ('' to 'abc' = 3, 'kitten' to 'sitting' = 3)
- isDomainLookalike: 'rbc.com' vs 'rЬc.com' (Cyrillic b) → true
- isDomainLookalike: 'rbc.com' vs 'google.com' → false

lib/url-analyzer.js:
- analyzeUrl('https://canada.ca') → verdict: 'safe'
- analyzeUrl('https://cra-refund-2026.xyz') → verdict: 'high' (suspicious TLD + CRA keyword)
- analyzeUrl('https://cra.gc.ca.refund-portal.xyz') → verdict: 'high' (subdomain spoofing)
- analyzeUrl('https://192.168.1.1/cra-login') → verdict: 'high' (IP address)
- analyzeUrl('https://rbc.com') → verdict: 'safe' (exact whitelist match)
- analyzeUrl('https://rЬc.com') → verdict: 'high' (homoglyph of rbc.com)

lib/message-analyzer.js:
- Gift card request → score ≥ 70, gift_card_payment_request rule fired
- Geek Squad template → score ≥ 75, geek_squad_exact_template fired
- iMessage Y-reply trick → score ≥ 70, imessage_evasion_reply_y fired
- CRA from gmail.com → score ≥ 45, cra_free_provider fired
- Legitimate bank email from correct domain → score < 30
- 407 ETR toll + non-whitelist link → toll_road_unpaid_link fired
- SIN request → sin_request fired
- RCMP from gmail.com → police_free_provider fired (weight 60)

Create a fixtures/ folder with sample message strings for each test case.
```

---

## QUICK REFERENCE: File Status

| File | Status |
|---|---|
| `data/whitelist.json` | ✅ Complete |
| `data/scam-sender-patterns.json` | ✅ Complete |
| `data/known-sender-domains.json` | ✅ Complete |
| `data/known-bad.json` | 🔴 Run prompt #10 |
| `data/scam-keywords.json` | 🔴 Run prompt #10 |
| `manifest.json` | 🔴 Run prompt #1 |
| `background/service-worker.js` | 🔴 Run prompts #1, then #9 |
| `content/content-script.js` | 🔴 Run prompt #1 |
| `content/overlay.css` | 🔴 Run prompt #1 |
| `lib/homoglyph.js` | 🔴 Run prompt #3 |
| `lib/url-analyzer.js` | 🔴 Run prompt #2 |
| `lib/content-analyzer.js` | 🔴 Run prompt #5 |
| `lib/message-analyzer.js` | 🔴 Run prompt #4 |
| `lib/i18n.js` | 🔴 Run prompt #11 |
| `popup/popup.html` | 🔴 Run prompts #1, then #7 |
| `popup/popup.js` | 🔴 Run prompt #7 |
| `popup/popup.css` | 🔴 Run prompt #7 |
| `warning/warning.html` | 🔴 Run prompts #1, then #6 |
| `warning/warning.js` | 🔴 Run prompt #6 |
| `options/options.html` | 🔴 Run prompt #8 |
| `options/options.js` | 🔴 Run prompt #8 |
| Tests | 🔴 Run prompt #12 |

## Recommended Build Order

```
1 → 3 → 2 → 10 → 9 → 4 → 5 → 6 → 7 → 8 → 11 → 12
```
Skeleton → Homoglyph → URL Analyzer → Data files → Update service
→ Message Analyzer → Content Analyzer → Warning page → Popup → Options
→ i18n → Tests
