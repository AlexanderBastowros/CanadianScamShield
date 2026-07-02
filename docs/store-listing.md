# Chrome Web Store listing — Canadian Scam Shield

Copy/paste source for the store listing and the required review disclosures.

## Name
Canadian Scam Shield

## Summary (≤132 chars)
Spots scams that impersonate the CRA, banks, Canada Post & more — on websites,
in pages, and in your email. All on your device.

## Category
Productivity (or Communication)

## Languages
English, French (Canada)

## Detailed description
Canadian Scam Shield helps you — and the people you help — avoid scams that
pretend to be Canadian organizations like the Canada Revenue Agency, your bank,
Service Canada, IRCC, Interac, or Canada Post.

It works in three ways, all on your device:

• Fake websites — warns you about look‑alike and fake Canadian sites before you
  trust them (look‑alike domains, fake “.gc.ca” addresses, and more).
• Scam pages — checks the page you’re on for the tricks scammers use, like fake
  refund notices, urgent threats, gift‑card demands, or a Social Insurance Number
  box on a non‑government site.
• Suspicious emails and texts — paste any message into the popup to check it, or
  let it quietly check the emails you open in Gmail and Outlook.

Warnings are calm and clear, explain what looked wrong in plain language, point
you to the real website, and include the Canadian Anti‑Fraud Centre’s number.
Everything is checked on your device — your browsing and your email are never
sent to us or anyone else.

Free forever. An optional Shield Pro subscription adds live phishing‑feed checks,
domain‑age checks, sensitivity controls, and custom block lists.

Not affiliated with the Government of Canada.

## Permission justifications (single purpose per item)
- **Host permission (all sites):** Required to read the address and visible
  content of pages the user visits in order to detect scam/phishing pages and
  display an in‑page warning. Data is analyzed locally and never transmitted.
- **Gmail/Outlook host access:** Required to read the email the user currently
  has open so it can be checked for scam patterns locally. User‑toggleable.
- **storage:** Save user settings and local caches on the device.
- **tabs / activeTab:** Show the warning page, toolbar badge, and
  popup status for the current tab.
- **alarms:** Schedule a once‑daily refresh of the bundled detection data.

## Data-use disclosures (Web Store privacy form)
- Does the item collect user data? **No** (free tier collects nothing).
- Personally identifiable info: **Not collected.**
- Web history / browsing activity: **Not collected / not transmitted** (analyzed
  locally only).
- Authentication info / financial info: only via **Stripe** for the optional paid
  subscription (email + payment handled by Stripe), not by the extension itself.
- Sold to third parties: **No.** Used for advertising: **No.**
- Note for reviewers: once a day the extension fetches updated *detection data
  files* (whitelist/keyword/rule JSON) from this project's public GitHub
  repository — no user data is sent. Optional Pro features (off by default) may
  send a *suspicious URL* to PhishTank and a *domain name* to a public RDAP
  service; see the privacy policy.

## Privacy policy URL
Publish `docs/privacy-policy.md` (e.g., as a GitHub Pages page) and link it here.

## Screenshots to capture (1280×800)
1. Full‑page warning on a look‑alike CRA site.
2. In‑page yellow banner on a medium‑risk page.
3. Popup “Check a message” showing a flagged email with reasons.
4. Gmail inline chip on a scam email.
5. Settings page (language, sensitivity, Shield Pro).

## Small promo / store assets
- 128×128 icon: `icons/icon128.png` (maple-leaf shield, transparent background).
- Optional 440×280 small promo tile.
