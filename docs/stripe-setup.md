# Shield Pro — Stripe + Cloudflare Worker Setup

The Shield Pro subscription ($3.99 CAD/month) is sold through Stripe Checkout on
the web (avoids the 30% browser-store cut). The backend is a single Cloudflare
Worker in `server/` — free tier is plenty.

## 1. Stripe (≈5 minutes)

1. Create a [Stripe](https://dashboard.stripe.com) account (or use test mode).
2. **Products → Add product**: name **Shield Pro**, recurring price
   **$3.99 CAD / month**. Copy the **price id** (`price_…`).
3. Keep the dashboard open — you'll add a webhook in step 3.

## 2. Deploy the worker

```bash
npm i -g wrangler
cd server
wrangler login
wrangler kv namespace create LICENSES     # copy the id into wrangler.toml
wrangler secret put STRIPE_SECRET_KEY     # sk_test_… for testing
wrangler secret put STRIPE_PRICE_ID       # price_… from step 1
wrangler deploy                            # note your worker URL
```

Then edit `wrangler.toml` → set `SUCCESS_URL`/`CANCEL_URL` to your real worker
URL and `wrangler deploy` again.

## 3. Stripe webhook

1. Dashboard → **Developers → Webhooks → Add endpoint**:
   `https://<your-worker-url>/webhook`
2. Events: `checkout.session.completed`, `customer.subscription.updated`,
   `customer.subscription.deleted`.
3. Copy the **signing secret** (`whsec_…`) →
   `wrangler secret put STRIPE_WEBHOOK_SECRET`.

## 4. Test (Stripe test mode)

1. `curl -X POST https://<worker-url>/create-checkout-session` → open the
   returned `url`.
2. Pay with test card **4242 4242 4242 4242** (any future expiry / CVC).
3. You land on `/success` and see a license key `CSS-XXXX-XXXX-XXXX-XXXX`.
4. `curl "https://<worker-url>/verify?key=CSS-…"` →
   `{"valid":true,"status":"active","plan":"shield_pro"}`.
5. Cancel the test subscription in Stripe → `/verify` flips to
   `"status":"inactive"` within seconds (webhook-driven revocation).

## 5. Point the extension at it

Set the API base in the extension (see `lib/pro.js` / options page) to your
worker URL. The flow end-to-end:

- Options → **Upgrade to Shield Pro** → `POST /create-checkout-session` →
  checkout opens in a new tab.
- After payment the success page shows the license key; the user pastes it into
  **Settings → Shield Pro → Activate**.
- The extension calls `GET /verify?key=…` on activation and daily thereafter,
  caching `{ proLicense, proStatus, proCheckedAt }` in `chrome.storage.sync`.
  If the network is down it keeps the last known status (grace, fail-closed to
  free tier only after the license is positively reported inactive).

## Security notes

- Webhook signatures are HMAC-verified with replay protection (5-min window).
- Licenses are revoked automatically when the subscription is cancelled or
  unpaid.
- The worker stores only the email Stripe provides, the Stripe customer/
  subscription ids, and the license status — no browsing data, ever.
- `/verify` is rate-limited per IP to deter key guessing.
