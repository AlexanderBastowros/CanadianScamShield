# Canadian Scam Shield

A Chrome extension (Manifest V3) that helps Canadians — especially seniors and
newcomers — spot scam websites impersonating Canadian institutions (CRA, banks,
Canada Post, Interac, IRCC, and more).

> **Framing:** This tool *helps you spot scams* — it does not block all scams or
> guarantee protection. It is not affiliated with the Government of Canada.

## Status — Phase 1a MVP

This is the first milestone: **live URL / website detection (Layer 1)** with a
warning screen, in-page banner, and a popup status panel. All analysis runs
locally on your device — no account, no servers, no tracking.

### What works now
- **Layer 1 URL analysis** on every navigation (`lib/url-analyzer.js`):
  whitelist match → known-bad match → homoglyph/lookalike scoring against
  high-value institutions → fake-government TLD enforcement → suspicious TLD,
  excessive hyphens, raw-IP, punycode, and subdomain-spoofing heuristics.
- **Verdict → UX response:** clean (clear badge) · low (badge) · medium (in-page
  banner) · high (full-page warning with explicit override).
- **Popup** showing the current tab's safety status with plain-language reasons.
- **Options** page: language (EN/FR) and a personal trusted-sites list.
- **EN-first, i18n-ready** strings via `lib/i18n.js` (French scaffolded).

### Out of scope for this milestone
Email/SMS message checker (Layer 3), page-content scanner (Layer 2), daily data
auto-update, full French translations, and all Shield Pro features
(PhishTank/WHOIS/SIN/auth-header, Stripe billing).

## Project layout
```
manifest.json              MV3 config
background/service-worker.js  navigation analysis + verdict dispatch + data loader
lib/url-analyzer.js        Layer 1 detection (pure, Node-testable)
lib/homoglyph.js           Unicode normalization + Levenshtein
lib/i18n.js                bilingual strings (EN complete, FR stub)
content/                   in-page warning banner + styles
warning/                   full-page block screen
popup/                     current-tab status + (stubbed) message checker tab
options/                   settings (language, personal whitelist)
data/whitelist.json        372 verified Canadian institutions
data/known-bad.json        confirmed-malicious seed (empty for now)
scripts/smoke-test.mjs     Node smoke test for the detection logic
docs/                      Phase 1 handoff + task prompts
```

## Load it in Chrome
1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this repository folder
4. Visit a site such as `https://www.canada.ca` (clean) or a crafted lookalike
   to see the warning flow.

## Run the detection tests (no browser needed)
```
node scripts/smoke-test.mjs
```
Covers homoglyph normalization, Levenshtein distances, and the key URL-verdict
cases (whitelist safe, Cyrillic lookalike, fake-CRA TLD, subdomain spoof, raw IP).

## Reference numbers
- Canadian Anti-Fraud Centre: **1-888-495-8501** ·
  antifraudcentre-centreantifraude.ca
