/**
 * server/worker.js
 * Canadian Scam Shield — Shield Pro subscription backend (Cloudflare Worker)
 *
 * Handles Stripe checkout, webhook-driven license issuance, and license
 * verification for the Shield Pro tier ($3.99/month).
 *
 * ── Extension-side contract ─────────────────────────────────────────────────
 *   EXTENSION_API_BASE = https://canadian-scam-shield-pro.YOUR-SUBDOMAIN.workers.dev
 *
 *   1. Options page "Upgrade" → POST {EXTENSION_API_BASE}/create-checkout-session
 *      → { url }  → extension opens url in a new tab (Stripe-hosted checkout).
 *   2. After payment, Stripe redirects to {SUCCESS_URL}?session_id=… which
 *      fetches GET /session-license?session_id=… → { licenseKey } and shows it.
 *   3. User pastes the key into Options → extension calls
 *      GET /verify?key=CSS-…  → { valid, status, plan } and caches the result
 *      in chrome.storage.sync as { proLicense, proStatus, proCheckedAt }.
 *
 * ── Bindings (wrangler.toml / dashboard) ────────────────────────────────────
 *   KV namespace:  LICENSES
 *   Secrets:       STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET
 *   Vars:          SUCCESS_URL, CANCEL_URL
 */

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...extraHeaders },
  });
}

/** Generates a license key like CSS-7XK2-9MQ4-RT8W-BHN3 (no 0/O/1/I). */
function generateLicenseKey() {
  const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
  const groups = [];
  for (let i = 0; i < 16; i += 4) groups.push(chars.slice(i, i + 4).join(''));
  return 'CSS-' + groups.join('-');
}

/** Constant-time string comparison (avoids timing side-channels on HMACs). */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

/** HMAC-SHA256 of `message` with `secret`, returned as lowercase hex. */
async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verifies a Stripe webhook signature header against the raw body.
 * Header format: "t=1700000000,v1=abcdef...,v1=..." — any matching v1 passes.
 * Rejects events older than 5 minutes (replay protection).
 */
async function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = Object.create(null);
  const v1s = [];
  for (const piece of sigHeader.split(',')) {
    const [k, v] = piece.split('=', 2);
    if (k === 't') parts.t = v;
    if (k === 'v1') v1s.push(v);
  }
  if (!parts.t || v1s.length === 0) return false;

  const ageSeconds = Math.abs(Date.now() / 1000 - Number(parts.t));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 300) return false;

  const expected = await hmacSha256Hex(secret, `${parts.t}.${rawBody}`);
  return v1s.some((v1) => timingSafeEqual(expected, v1));
}

/** Calls the Stripe REST API with form-encoded params. Returns parsed JSON. */
async function stripeRequest(env, method, path, params = null) {
  const init = {
    method,
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  };
  if (params) {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(params).toString();
  }
  const res = await fetch('https://api.stripe.com' + path, init);
  const body = await res.json();
  if (!res.ok) {
    // Surface Stripe's error message but never our secret key.
    throw new Error(body?.error?.message || `Stripe API error (${res.status})`);
  }
  return body;
}

/**
 * Best-effort per-IP rate limit using KV (60-second window).
 * KV is eventually consistent so this is a soft limit — good enough to deter
 * brute-force key guessing, not a hard security boundary.
 */
async function rateLimited(env, ip, limit = 30) {
  const key = `rl_${ip}`;
  try {
    const current = Number((await env.LICENSES.get(key)) || '0');
    if (current >= limit) return true;
    await env.LICENSES.put(key, String(current + 1), { expirationTtl: 60 });
  } catch {
    // KV hiccup — fail open for availability.
  }
  return false;
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async function handleCreateCheckoutSession(request, env) {
  let email;
  try {
    const body = await request.json();
    email = body?.email;
  } catch {
    /* empty body is fine */
  }

  const params = {
    mode: 'subscription',
    'line_items[0][price]': env.STRIPE_PRICE_ID,
    'line_items[0][quantity]': '1',
    success_url: `${env.SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: env.CANCEL_URL,
    allow_promotion_codes: 'true',
  };
  if (email) params.customer_email = email;

  const session = await stripeRequest(env, 'POST', '/v1/checkout/sessions', params);
  return json({ url: session.url });
}

async function handleWebhook(request, env) {
  const rawBody = await request.text();
  const ok = await verifyStripeSignature(
    rawBody,
    request.headers.get('stripe-signature'),
    env.STRIPE_WEBHOOK_SECRET
  );
  if (!ok) return json({ error: 'invalid signature' }, 400);

  const event = JSON.parse(rawBody);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const licenseKey = generateLicenseKey();
    const record = {
      email: session.customer_details?.email || session.customer_email || null,
      customerId: session.customer || null,
      subscriptionId: session.subscription || null,
      status: 'active',
      created: new Date().toISOString(),
    };
    await env.LICENSES.put(licenseKey, JSON.stringify(record));
    if (record.subscriptionId) {
      await env.LICENSES.put(`sub_${record.subscriptionId}`, licenseKey);
    }
  } else if (
    event.type === 'customer.subscription.deleted' ||
    (event.type === 'customer.subscription.updated' &&
      ['canceled', 'unpaid', 'incomplete_expired'].includes(event.data.object.status))
  ) {
    const subId = event.data.object.id;
    const licenseKey = await env.LICENSES.get(`sub_${subId}`);
    if (licenseKey) {
      const raw = await env.LICENSES.get(licenseKey);
      if (raw) {
        const record = JSON.parse(raw);
        record.status = 'inactive';
        await env.LICENSES.put(licenseKey, JSON.stringify(record));
      }
    }
  }
  // Unhandled event types are acknowledged so Stripe stops retrying.
  return json({ received: true });
}

async function handleSessionLicense(url, env) {
  const sessionId = url.searchParams.get('session_id');
  if (!sessionId) return json({ error: 'missing session_id' }, 400);

  const session = await stripeRequest(
    env, 'GET', `/v1/checkout/sessions/${encodeURIComponent(sessionId)}`
  );
  if (session.payment_status !== 'paid') {
    return json({ error: 'payment not completed' }, 402);
  }
  const licenseKey = session.subscription
    ? await env.LICENSES.get(`sub_${session.subscription}`)
    : null;
  if (!licenseKey) {
    // Webhook may not have arrived yet — tell the page to retry shortly.
    return json({ error: 'license not ready yet, retry shortly' }, 404);
  }
  return json({ licenseKey });
}

async function handleVerify(request, url, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await rateLimited(env, ip)) return json({ error: 'rate limited' }, 429);

  const key = (url.searchParams.get('key') || '').trim().toUpperCase();
  if (!/^CSS(-[2-9A-HJKMNP-Z]{4}){4}$/.test(key)) {
    return json({ valid: false, status: 'unknown', plan: 'shield_pro' });
  }
  const raw = await env.LICENSES.get(key);
  if (!raw) return json({ valid: false, status: 'unknown', plan: 'shield_pro' });

  const record = JSON.parse(raw);
  return json({
    valid: record.status === 'active',
    status: record.status === 'active' ? 'active' : 'inactive',
    plan: 'shield_pro',
  });
}

// ---------------------------------------------------------------------------
// Success page (served at GET /success; also mirrored in server/success.html)
// ---------------------------------------------------------------------------

const SUCCESS_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shield Pro — Thank you</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background:#f7f7f5; color:#1a1a1a; margin:0; padding:40px 20px;
         font-size:18px; line-height:1.6; }
  .card { max-width:560px; margin:0 auto; background:#fff; border-radius:10px;
          padding:32px; box-shadow:0 2px 10px rgba(0,0,0,.08); }
  h1 { color:#b3261e; font-size:26px; margin-top:0; }
  .key-box { display:flex; gap:10px; align-items:center; margin:20px 0;
             background:#f0f0ee; border:2px solid #b3261e; border-radius:8px;
             padding:16px; }
  #license-key { font-family:ui-monospace, Menlo, Consolas, monospace;
                 font-size:20px; font-weight:700; letter-spacing:1px;
                 word-break:break-all; flex:1; }
  button { font-size:16px; padding:12px 18px; border:0; border-radius:6px;
           background:#b3261e; color:#fff; cursor:pointer; min-height:48px; }
  button:focus-visible { outline:3px solid #1a73e8; outline-offset:2px; }
  ol { padding-left:22px; }
  .muted { color:#555; font-size:15px; }
</style>
</head>
<body>
<div class="card">
  <h1>Thank you — Shield Pro is yours</h1>
  <p>Your subscription is active. Here is your license key:</p>
  <div class="key-box">
    <span id="license-key" aria-live="polite">Loading…</span>
    <button id="copy-btn" type="button">Copy</button>
  </div>
  <p>To activate:</p>
  <ol>
    <li>Open the <strong>Canadian Scam Shield</strong> extension</li>
    <li>Go to <strong>Settings → Shield Pro</strong></li>
    <li>Paste your license key and click <strong>Activate</strong></li>
  </ol>
  <p class="muted">Keep this key safe — it is your proof of subscription.
     You can return to this page from your Stripe receipt email.</p>
</div>
<script>
  (function () {
    var keyEl = document.getElementById('license-key');
    var copyBtn = document.getElementById('copy-btn');
    var sessionId = new URLSearchParams(location.search).get('session_id');
    var attempts = 0;

    function load() {
      if (!sessionId) { keyEl.textContent = 'Missing session — contact support.'; return; }
      fetch('/session-license?session_id=' + encodeURIComponent(sessionId))
        .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
        .then(function (res) {
          if (res.ok && res.body.licenseKey) {
            keyEl.textContent = res.body.licenseKey;
          } else if (attempts++ < 10) {
            // Webhook may lag checkout by a few seconds — retry.
            setTimeout(load, 2000);
          } else {
            keyEl.textContent = 'Key not ready — refresh this page in a minute.';
          }
        })
        .catch(function () { keyEl.textContent = 'Could not load key — refresh to retry.'; });
    }

    copyBtn.addEventListener('click', function () {
      navigator.clipboard.writeText(keyEl.textContent).then(function () {
        copyBtn.textContent = 'Copied ✓';
        setTimeout(function () { copyBtn.textContent = 'Copy'; }, 2000);
      });
    });

    load();
  })();
</script>
</body>
</html>`;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (request.method === 'POST' && url.pathname === '/create-checkout-session') {
        return await handleCreateCheckoutSession(request, env);
      }
      if (request.method === 'POST' && url.pathname === '/webhook') {
        return await handleWebhook(request, env);
      }
      if (request.method === 'GET' && url.pathname === '/session-license') {
        return await handleSessionLicense(url, env);
      }
      if (request.method === 'GET' && url.pathname === '/verify') {
        return await handleVerify(request, url, env);
      }
      if (request.method === 'GET' && url.pathname === '/success') {
        return new Response(SUCCESS_PAGE, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }
      if (request.method === 'GET' && url.pathname === '/') {
        return json({ service: 'canadian-scam-shield-pro', ok: true });
      }
      return json({ error: 'not found' }, 404);
    } catch (err) {
      console.error('worker error:', err.message);
      return json({ error: err.message }, 500);
    }
  },
};
