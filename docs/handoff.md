# Canadian Scam Shield — Phase 1 Handoff

> **Scope:** Chrome Extension (Manifest V3) only. Phase 2 (native iOS/Android) is documented in the project plan but excluded from this handoff.

---

## Product Vision

A Chrome extension that protects Canadians — especially seniors and newcomers — from scams targeting Canadian institutions (CRA, Service Canada, IRCC, Canada Post, Interac, major banks, Geek Squad/Best Buy).

**What it is:** A focused, single-purpose scam warning tool.
**What it is not:** Antivirus, password manager, or tracker blocker.

**Core principle:** Educate rather than just block. Bias toward warnings over hard blocks until data is solid. False positives destroy trust.

---

## Business Model (Freemium)

### Free "Shield" Tier
All analysis runs locally — no account, no server costs.
- Whitelist matching (exact domain lookup)
- Lookalike / homoglyph detection
- Basic email/SMS paste checker
- TLD enforcement (`.gc.ca` / `.canada.ca` rules)
- CAFC reporting integration

### Paid "Shield Pro" — $3.99/month (Stripe, web-based — avoids 30% app store cut)
Features with real API costs or false-positive risk that requires tunable controls:
- Live PhishTank feed
- WHOIS domain age checks
- SIN field detection on non-gov sites
- Auth header analysis (SPF/DKIM/DMARC)
- Sender domain reputation lookups
- Link extraction scanning
- Sensitivity controls (Strict / Balanced / Permissive)
- Custom whitelist/blocklist management

### Gate logic rationale
Free features are local-only — zero marginal cost. Pro features either hit external APIs (real cost) or require sensitivity tuning to manage false-positive risk, which needs a paid relationship to support.

### Upgrade moments (6 mapped, tied to genuine capability gaps)
1. User pastes a message and domain age check would help but isn't available
2. User visits a suspicious URL and PhishTank would confirm/clear it
3. User asks why a site wasn't caught (answer: SIN field detection is Pro)
4. User reports a false positive (sensitivity controls are Pro)
5. User wants to whitelist a personal banking subdomain
6. User wants to block a specific site permanently

---

## Finalized File Architecture

```
canadian-scam-shield/
├── manifest.json
├── background/
│   └── service-worker.js       # URL checks, DB sync, message routing
├── content/
│   ├── content-script.js       # Page scanning, banner injection
│   └── overlay.css             # Warning UI styles
├── popup/
│   ├── popup.html              # Main UI: status + email/SMS checker
│   ├── popup.js
│   └── popup.css
├── warning/
│   └── warning.html            # Full-page block screen
├── options/
│   └── options.html            # User settings, sensitivity
├── data/
│   ├── whitelist.json          # ✅ COMPLETE — 280+ verified Canadian institutions
│   ├── scam-sender-patterns.json  # ✅ COMPLETE — 35 weighted detection rules
│   ├── known-sender-domains.json  # ✅ COMPLETE — legit sending domains per org
│   └── known-bad.json          # TODO — seed with CAFC/PhishTank blocked list
└── lib/
    ├── url-analyzer.js         # TODO
    ├── content-analyzer.js     # TODO
    ├── message-analyzer.js     # TODO
    └── homoglyph.js            # TODO
```

---

## Finalized Data Schemas

### whitelist.json (COMPLETE — v1.0.0)

280+ verified Canadian institutions. Used by all three detection layers.

```json
{
  "version": "1.0.0",
  "last_updated": "2026-05-27",
  "institutions": [
    {
      "domain": "cra-arc.gc.ca",
      "name": "Canada Revenue Agency",
      "category": "federal_government",
      "official_url": "https://www.canada.ca/en/revenue-agency.html",
      "high_value": true
    }
  ]
}
```

**Categories covered:** `federal_government`, `provincial_government`, `municipal_government`, `law_enforcement`, `bank`, `credit_union`, `payments`, `insurance`, `telecom`, `utilities`, `shipping`, `retail`, `tech`, `food_delivery`, `rideshare`, `travel`, `education`, `healthcare`, `media`, `social_media`, `streaming`, `marketplace`, `employment`, `credit_bureau`

**`high_value: true`** = frequent impersonation target → stricter lookalike scoring applied.

Key high-value entries: `cra-arc.gc.ca`, `servicecanada.gc.ca`, `ircc.canada.ca`, `cbsa-asfc.gc.ca`, `rcmp-grc.gc.ca`, `canadapost-postescanada.ca`, all Big 6 banks, `interac.ca`, `bestbuy.ca`, `geeksquad.ca`

---

### scam-sender-patterns.json (COMPLETE — v1.1.0)

35 detection rules with weights. Sources: CAFC bulletins 2024–2026, r/Scams samples, 407 ETR fraud bulletins, CBC Go Public, University of Waterloo CRA targeting samples.

**Scoring thresholds:**
```
< 30   → No warning
30–54  → Low: subtle icon badge change
55–79  → Medium: persistent warning banner
80–100 → High: full-page block (requires explicit override)
```
Thresholds shift ±15 based on user sensitivity setting (Strict / Balanced / Permissive).

**Rule types and key rules:**

| Rule ID | Weight | What it catches |
|---|---|---|
| `geek_squad_exact_template` | 75 | Exact Geek Squad/Norton/McAfee invoice scam template |
| `gift_card_payment_request` | 70 | Gift card payment demands |
| `executable_attachment` | 75 | .exe, .scr, .vbs, .iso, .lnk attachments |
| `imessage_evasion_reply_y` | 70 | "Reply Y then exit" iMessage bypass trick |
| `punycode_institutional_claim` | 65 | xn-- domains claiming to be institutions |
| `domain_lookalike_high_value` | 60 | Levenshtein/homoglyph near-matches of whitelisted orgs |
| `auth_failure_known_brand` | 65 | SPF/DKIM/DMARC failure for claimed brand |
| `credential_request_otp` | 65 | Requests for 2FA/OTP codes |
| `sin_request` | 65 | Any email asking for SIN |
| `sin_included_in_body` | 60 | Scammer showing victim's own SIN to seem legit (CAFC 2024 pattern) |
| `toll_road_unpaid_link` | 65 | 407 ETR / A25 unpaid toll smishing (top 2025 scam) |
| `police_free_provider` | 60 | RCMP/police claiming Gmail/Outlook address |
| `etransfer_loading_screen` | 65 | Fake Interac e-Transfer processing page |
| `canada_post_redelivery_fee` | 60 | "Small redelivery fee" Canada Post scam |
| `ircc_free_provider` | 50 | Free-provider email claiming IRCC (newcomer targeting) |
| `a25_toll_bridge_scam` | 60 | A25 Laval-Montréal bridge toll scam (Quebec-specific) |
| `alberta_rebate_text_scam` | 55 | Alberta affordability/energy rebate scam |

**Rule composition model:** Rules are narrow and composable. A real scam typically trips 3–5 rules. A legitimate message trips 0–1. `perfect_grammar_with_red_flags` (weight 15) is a tiebreaker only — good grammar is no longer exculpatory.

---

### known-sender-domains.json (COMPLETE — v1.0.0)

30 organizations with verified sending/reply-to domains. Used exclusively for **mismatch detection** — if a message claims to be from org X but the From/Reply-To domain isn't in org X's set, that's a signal.

**⚠️ CRITICAL USAGE NOTE:** A matching domain does NOT prove legitimacy (From headers are trivially spoofable). Only SPF/DKIM/DMARC is reliable proof. This file is a heuristic only.

```json
{
  "id": "cra",
  "aliases": ["CRA", "Canada Revenue Agency", "Revenue Canada", "ARC", ...],
  "sending_domains": ["cra-arc.gc.ca", "canada.ca"],
  "reply_to_domains": ["cra-arc.gc.ca", "canada.ca"],
  "official_phone": "1-800-959-8281"
}
```

**Organizations covered:** CRA, Service Canada, IRCC, CBSA, RCMP, Canada Post, Interac, RBC, TD, Scotiabank, BMO, CIBC, National Bank, Desjardins, Tangerine, Simplii, Amex Canada, PayPal, Wealthsimple, Bell, Rogers, TELUS, Amazon CA, Best Buy CA, Geek Squad, Norton, McAfee, Microsoft, Apple, Netflix

---

## Detection Layer Architecture

### Layer 1 — URL Analysis (every navigation, ~5ms target)
```
1. Normalize URL → extract apex domain
2. Exact match whitelist.json → SAFE, exit
3. Exact match known-bad.json → BLOCK
4. Homoglyph normalize → Levenshtein(2) vs high_value whitelist entries → score
5. TLD enforcement: any domain containing "cra", "canada-revenue", etc. must end in .gc.ca or .canada.ca
6. Pattern flags: excessive hyphens, IP in URL, punycode (xn--), suspicious TLDs (.xyz, .top, .click)
7. [Pro] Domain age API call (cache 7 days) → flag if < 90 days + institutional claim
8. Return: { safe | low | medium | high, reason[], realSiteUrl? }
```

### Layer 2 — Page Content Scanning (post DOM load)
```
1. Extract: visible text, <title>, meta description, form field labels/names
2. Score against scam-sender-patterns.json keyword categories:
   - Impersonation terms (CRA, GST/HST refund, Service Canada, etc.)
   - Urgency triggers (warrant, arrest, suspended, 24 hours)
   - Payment red flags (gift cards, Bitcoin, e-Transfer to individual)
   - Credential harvesting (SIN field on non-.gc.ca site)
3. [Pro] Detect SIN input fields on non-whitelisted domains
4. Layer 1 score + Layer 2 score → combined threshold check
5. Inject banner / trigger full-page warning accordingly
```

### Layer 3 — Email/SMS Paste Checker (user-initiated, popup)
```
1. User pastes raw message text into popup
2. Parse: From/display name, Reply-To, subject, body, embedded links
3. Run applicable rules from scam-sender-patterns.json
4. Cross-reference known-sender-domains.json for display-name vs domain mismatch
5. [Pro] Auth header parse (SPF/DKIM/DMARC result lines)
6. Return: risk score, fired rule explanations in plain language, official contact info
```

---

## UX Response Model

| Score | UX Response | Override? |
|---|---|---|
| < 30 | Nothing / clean badge | — |
| 30–54 | Icon badge colour change, details on click | Always |
| 55–79 | Persistent yellow banner with reason + real site link | Yes, easy |
| 80–100 | Full-page block (warning.html), prominent override link | Yes, explicit click |

Every warning includes:
- What triggered it (plain language from rule's `user_explanation`)
- What the real site is (if `official_url` is known)
- CAFC reporting prompt: 1-888-495-8501 or antifraudcentre-centreantifraude.ca

---

## Manifest V3 Constraints (Design Inputs)

- **No persistent background pages** → service worker wakes on events, must be stateless
- **`declarativeNetRequest` rule caps** → can't block every bad URL via DNR alone; use programmatic checks in the service worker instead
- **Content script injection** → use `run_at: document_idle` for Layer 2 to avoid blocking page load
- **Storage:** `chrome.storage.local` for cached data; `chrome.storage.sync` for user settings (≤100KB)
- **CSP in extension pages** → no inline scripts in popup.html / warning.html / options.html; all JS must be in separate files

---

## Data Update Strategy

- **Bundle at build time:** `whitelist.json`, `scam-sender-patterns.json`, `known-sender-domains.json`
- **Daily background fetch:** GitHub-hosted raw JSON (same files) → diff and update `chrome.storage.local`
- **Update URL pattern:** `https://raw.githubusercontent.com/[org]/canadian-scam-shield-data/main/[file].json`
- **Cache TTL:** 24h for pattern updates, 7 days for domain age API responses
- **Fallback:** If fetch fails, continue with bundled version — never fail open

---

## Bilingual (EN/FR) Requirements

- All user-facing strings must have EN and FR variants
- Language setting stored in `chrome.storage.sync`
- Default to browser language (`navigator.language`), fallback to EN
- Rule `user_explanation` fields will need FR translations added to scam-sender-patterns.json
- Warning UI and popup UI must be tested in both languages (string length differs significantly)

---

## Legal / Compliance Notes

- **Do not claim affiliation with the Government of Canada.** No Canadian flag or IRCC/CRA wordmark in the UI.
- **No third-party logos without permission** — reference institution names in text only.
- **Liability framing:** "Helps you spot scams" — never "blocks all scams" or "protects you from."
- **Privacy:** All analysis local by default. No telemetry. If PhishTank opt-in is added, URL is sent to PhishTank — must be disclosed in privacy policy.
- **CAFC integration** is informational only (phone number + link). Not an API integration that transmits user data.

---

## Accessibility Requirements

Primary audience includes older Canadians. Warnings must be:
- Large, readable font (minimum 16px body, 20px+ for critical warnings)
- High contrast (WCAG AA minimum, AAA preferred for warnings)
- Not panic-inducing — calm, informative tone, not "DANGER!!!"
- No auto-dismissing alerts — user must explicitly acknowledge
- Keyboard navigable throughout

---

## Open To-Do List (Phase 1)

### 🔴 Blocking (MVP — Phase 1a)
- [ ] `manifest.json` — MV3 config, permissions, content script registration
- [ ] `background/service-worker.js` — URL check on navigation, wake/sleep lifecycle
- [ ] `lib/url-analyzer.js` — Layers 1 whitelist match, known-bad match, TLD enforcement
- [ ] `lib/homoglyph.js` — Unicode normalization + Levenshtein scoring
- [ ] `warning/warning.html` — Full-page block screen with override
- [ ] `content/content-script.js` — Banner injection (medium-confidence cases)
- [ ] `content/overlay.css` — Warning banner styles
- [ ] `popup/popup.html` + `popup.js` + `popup.css` — Status display
- [ ] `data/known-bad.json` — Seed list (can start with empty array `[]`, populate from CAFC/PhishTank)

### 🟡 Phase 1b (v1.0)
- [ ] `lib/content-analyzer.js` — Layer 2 page content scoring
- [ ] `lib/message-analyzer.js` — Layer 3 email/SMS paste checker
- [ ] Popup tab: Email/SMS checker UI
- [ ] `options/options.html` — Settings page (sensitivity, language, whitelist/blocklist management)
- [ ] Daily background fetch of data files from GitHub
- [ ] French translations for all `user_explanation` strings in `scam-sender-patterns.json`
- [ ] French UI strings across all pages
- [ ] Badge icon states (clean / low / medium / high)

### 🟢 Phase 1c (Pro + Launch)
- [ ] Stripe web subscription flow for Shield Pro
- [ ] PhishTank API integration (Pro gate)
- [ ] WHOIS domain age API integration (Pro gate)
- [ ] SIN field detection on page content (Pro gate)
- [ ] Auth header parsing in message analyzer (Pro gate)
- [ ] Chrome Web Store listing, screenshots, privacy policy
- [ ] Firefox port (manifest adjustments, test suite)
- [ ] `scam-keywords.json` — Standalone keyword library for Layer 2 (currently embedded in `scam-sender-patterns.json`; extract for reuse)

### 🔵 Infrastructure
- [ ] GitHub repo: `canadian-scam-shield-data` — hosts live-updated JSON files
- [ ] CI: validate JSON schema on PR to data repo
- [ ] Versioning strategy for data files (semver, breaking changes trigger extension update)

---

## Key Engineering Decisions (Final)

| Decision | Choice | Rationale |
|---|---|---|
| Extension framework | Manifest V3 | Required for Chrome Web Store; no persistent background |
| Background page | Service Worker | MV3 requirement |
| Analysis location | Client-side only (free tier) | Zero server cost; privacy-preserving |
| Data hosting | GitHub raw JSON | Free, versionable, community-contributable |
| Billing | Stripe (web) | Avoids 30% browser extension store cut |
| Lookalike algo | Levenshtein distance ≤ 2 + homoglyph normalization | Catches character swaps and Unicode spoofing |
| Threshold model | Weighted score (0–100) with 3 bands | Composable rules; tunable with sensitivity setting |
| Sensitivity control | ±15 threshold shift | Simple, understandable by non-technical users |
| False-positive bias | Warn > Block until data is solid | Trust is the product |

---

## Reference Numbers

- **CAFC phone:** 1-888-495-8501
- **CAFC website:** antifraudcentre-centreantifraude.ca
- **CRA legitimate phone:** 1-800-959-8281
- **407 ETR legitimate site:** 407etr.com (NOT a link in any text message)
- **Real Interac e-Transfer sender:** notify.payments.interac.ca

---

## Data File Locations (in this project)

| File | Status | Path |
|---|---|---|
| whitelist.json | ✅ Complete | `/data/whitelist.json` |
| scam-sender-patterns.json | ✅ Complete | `/data/scam-sender-patterns.json` |
| known-sender-domains.json | ✅ Complete | `/data/known-sender-domains.json` |
| known-bad.json | 🔴 TODO | `/data/known-bad.json` |
| scam-keywords.json | 🟡 To extract | `/data/scam-keywords.json` |
