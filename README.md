# Canadian Scam Shield

A Chrome extension (Manifest V3) that helps Canadians — especially seniors and
newcomers — spot scams impersonating Canadian institutions (CRA, Service Canada,
IRCC, Canada Post, Interac, the big banks, Geek Squad/Best Buy, and more).

> **Framing:** this tool *helps you spot scams* — it does not block all scams or
> guarantee protection, and it is not affiliated with the Government of Canada.

## What it does

Three detection layers, all running locally in the free tier (no account, no
servers, no tracking):

- **Layer 1 — websites (URL):** whitelist of 372 verified Canadian institutions,
  homoglyph/look-alike detection, fake-`.gc.ca` enforcement, suspicious TLDs,
  raw-IP, punycode, and subdomain-spoofing heuristics.
- **Layer 2 — page content:** scores the loaded page against scam keyword
  categories (impersonation / urgency / payment) plus structural credential
  traps (Social Insurance Number fields on non-government sites, passwords over
  HTTP, CVV outside payment processors), and combines with the Layer 1 score.
- **Layer 3 — message checker:** a 39-rule engine (built from CAFC bulletins and
  real 2024–2026 scam samples) explains in plain language what's suspicious and
  gives you the organization's real contact details. Two ways to use it:
  - **Paste** an email or text into the popup, or
  - **Automatic webmail scanning** — when you open an email in Gmail or Outlook
    on the web, the extension reads that open message and shows an inline warning
    chip if it looks like a scam. The email is analyzed **entirely on your
    device** and is never sent anywhere; you can turn this off in Settings.

Responses scale with confidence: a quiet badge → a dismissible banner → a
full-page warning with an explicit override. Bilingual (English/French)
throughout.

## Free vs Shield Pro

| | Free "Shield" | Shield Pro — $3.99/mo |
|---|---|---|
| All three detection layers | ✅ | ✅ |
| SIN-field detection | ✅ | ✅ |
| Sensitivity control (Strict/Balanced/Permissive) | — | ✅ |
| Custom block list | — | ✅ |
| Live PhishTank lookups | — | ✅ |
| Domain-age (WHOIS/RDAP) checks | — | ✅ |
| Auth-header (SPF/DKIM/DMARC) analysis | — | ✅ |

Billing is handled on the web via Stripe (see `docs/stripe-setup.md`) to avoid
browser-store cuts. The backend is a single Cloudflare Worker in `server/`.

## Project layout
```
manifest.json                 MV3 config (v1.0.0)
background/service-worker.js   analysis pipeline, routing, data updates, alarms
lib/
  url-analyzer.js              Layer 1 (pure, tested)
  content-analyzer.js          Layer 2 (pure, tested)
  message-analyzer.js          Layer 3 rule engine (pure, tested)
  homoglyph.js                 Unicode normalize + Levenshtein
  i18n.js                      EN/FR strings (complete)
  pro.js                       Shield Pro license state
  pro-checks.js                PhishTank + RDAP domain-age (Pro)
content/                       in-page warning banner
warning/                       full-page block screen
popup/                         status tab + message checker
options/                       settings: language, lists, sensitivity, Pro
data/                          whitelist (372), patterns (39 rules), sender
                               domains (30), keywords, known-bad
server/                        Cloudflare Worker: Stripe checkout + licenses
scripts/smoke-test.mjs         43 Node assertions across all three layers
test/                          local fake pages for manual testing
docs/                          handoff, task prompts, Stripe setup
```

## Load it in Chrome
1. `chrome://extensions` → enable **Developer mode**
2. **Load unpacked** → select this repository folder
3. Visit `https://www.canada.ca` (clean) or serve the test pages (below).

## Test
```
node scripts/smoke-test.mjs          # 43 assertions across all 3 layers
python3 -m http.server 8000          # then open the test pages over http://
```
- `http://localhost:8000/test/scam-test-page.html` → full-page warning
- `http://localhost:8000/test/benign-test-page.html` → no warning
- Popup → **Check a message** → paste a scam email/text to see Layer 3.

## Data updates
The five JSON data files are bundled, and the service worker refreshes them daily
from this repo's `master/data/` over GitHub raw (version-gated, fail-closed).

## Privacy
Free-tier analysis is entirely local — no browsing data, URLs, or messages leave
your device, including emails read by the Gmail/Outlook scanner. The only network
calls are: the daily data refresh (GitHub), and — **only if you opt in as a Pro
user** — PhishTank URL lookups and RDAP domain-age checks. No telemetry, ever.

## Reference numbers
- Canadian Anti-Fraud Centre: **1-888-495-8501** ·
  antifraudcentre-centreantifraude.ca
- CRA legitimate line: 1-800-959-8281
