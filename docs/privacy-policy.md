# Privacy Policy — Canadian Scam Shield

**Effective date:** 2026-06-11

Canadian Scam Shield ("the extension") helps you spot scams that impersonate
Canadian organizations. This policy explains exactly what the extension does and
does not do with your information. The short version: **analysis happens on your
device, and we do not collect, sell, or transmit your browsing or your email.**

## What the extension processes — and where

| Data | Where it's processed | Leaves your device? |
|---|---|---|
| Addresses (URLs) of pages you visit | On your device | No |
| Content of pages you open | On your device | No |
| Emails you open in Gmail/Outlook (free webmail scanning) | On your device | No |
| Messages you paste into the checker | On your device | No |

All scam detection (Layers 1–3) runs locally in the extension. The free version
makes **no network request that contains your browsing or message content.**

## What is stored on your device

Stored via the browser's extension storage, on your device/your browser profile:

- Your settings: language, sensitivity, custom trusted/blocked sites, the
  email-scanning toggle, and the PhishTank opt-in/app key.
- Your Shield Pro license key and its last-known status.
- A local cache of the threat-data files and the "last updated" time.
- Per-session "continue anyway" overrides (cleared when you close the browser).

There is **no analytics, no telemetry, and no account** in the free version.

## Network connections the extension makes

1. **Daily threat-data refresh** — downloads the latest detection data
   (whitelist, scam patterns, etc.) from this project's public GitHub
   repository. This is a one-way download; **no information about you is sent.**
2. **Shield Pro — PhishTank (opt-in only):** if you turn on PhishTank checking
   and provide a key, the address of a *suspicious* site is sent to PhishTank to
   compare against known phishing sites. Off by default.
3. **Shield Pro — domain-age check:** for a *borderline* site, the domain name
   (not the full URL, not page content) is sent to a public RDAP service to learn
   how recently it was registered. Pro only.
4. **Shield Pro — billing:** subscriptions are handled by Stripe. To create and
   verify a subscription, your email and license key are processed by Stripe and
   our license server. Billing data is governed by
   [Stripe's privacy policy](https://stripe.com/privacy).

The free tier uses only connection #1.

## Permissions, and why we ask for them

- **Read and change data on websites (`<all_urls>` / host access):** to check the
  address and content of pages you visit for scam signals, and to show an in-page
  warning. We never transmit this.
- **Gmail / Outlook access:** to read the email you currently have open and warn
  you if it looks like a scam. Analyzed locally; you can turn it off in Settings.
- **Storage:** to save your settings and caches on your device.
- **Tabs / activeTab / scripting:** to show the warning page, badge, and popup
  for the current tab.
- **Alarms:** to schedule the once-a-day data refresh.

## Data retention

Caches expire automatically (domain-age results after ~7 days, PhishTank results
after ~24 hours). Session overrides are cleared when the browser closes. You can
clear all stored settings by removing the extension.

## Children

The extension is a general-audience safety tool and is not directed at children.

## Changes

If this policy changes, the effective date above will be updated and the new
version published in the project repository.

## Contact

Questions or privacy requests: open an issue at
https://github.com/AlexanderBastowros/CanadianScamShield/issues
