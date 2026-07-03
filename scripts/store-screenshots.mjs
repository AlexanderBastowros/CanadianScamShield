/**
 * scripts/store-screenshots.mjs
 *
 * Generates the five 1280×800 Chrome Web Store screenshots listed in
 * docs/store-listing.md into docs/store-assets/, by loading the unpacked
 * extension in a real Chromium (same harness as scripts/e2e.mjs) and driving
 * each surface:
 *
 *   1. Full-page warning on a look-alike CRA site
 *   2. In-page banner on a medium-risk page (reasons expanded)
 *   3. Popup "Check a message" with a flagged email
 *   4. Gmail inline chip on a scam email (served via request interception)
 *   5. Settings page (Pro unlocked so every section is visible)
 *
 * Manual tooling — not part of the test suite or CI.
 * Run: node scripts/store-screenshots.mjs
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, mkdirSync, rmSync, createReadStream, statSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import http from 'node:http';

const SELF = fileURLToPath(import.meta.url);
const ROOT = join(dirname(SELF), '..');
const OUT_DIR = join(ROOT, 'docs', 'store-assets');
const SIZE = { width: 1280, height: 800 };

// Re-exec under Xvfb when there is no X display (headed browser required).
if (!process.env.DISPLAY && !process.env.CSS_XVFB) {
  const hasXvfb = spawnSync('sh', ['-c', 'command -v xvfb-run'], { stdio: 'ignore' }).status === 0;
  if (hasXvfb) {
    const r = spawnSync('xvfb-run', ['-a', process.execPath, SELF], {
      stdio: 'inherit',
      env: { ...process.env, CSS_XVFB: '1' },
    });
    process.exit(r.status ?? 1);
  }
}

const { chromium } = await import('playwright');

function resolveChromeBinary() {
  if (process.env.CSS_CHROME_BIN && existsSync(process.env.CSS_CHROME_BIN)) return process.env.CSS_CHROME_BIN;
  const cft = join(homedir(), '.cache', 'cft', 'chrome-linux64', 'chrome');
  if (existsSync(cft)) return cft;
  return undefined;
}

const MIME = { html: 'text/html', js: 'text/javascript', css: 'text/css', json: 'application/json', png: 'image/png' };
function startStaticServer(root) {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent((req.url || '/').split('?')[0]).replace(/^(\.\.[/\\])+/, '');
    const file = join(root, rel);
    try {
      if (statSync(file).isFile()) {
        res.setHeader('Content-Type', MIME[file.split('.').pop()] || 'text/plain; charset=utf-8');
        return createReadStream(file).pipe(res);
      }
    } catch { /* fall through */ }
    res.statusCode = 404;
    res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, { timeout = 10000, interval = 150 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try { const v = await fn(); if (v) return v; } catch { /* keep polling */ }
    await sleep(interval);
  }
  return false;
}

async function getSW(context) {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
  await waitFor(async () => {
    try { return await sw.evaluate(() => !!(globalThis.chrome && chrome.storage && chrome.tabs)); }
    catch { return false; }
  }, { timeout: 10000, interval: 100 });
  return sw;
}

const GMAIL_SCAM = `<!doctype html><html><body style="font-family:Roboto,Arial,sans-serif;background:#fff;max-width:820px;margin:24px auto;">
  <div class="bq9"><h2 class="hP" style="font-weight:400;">Unpaid toll notice — immediate payment required</h2></div>
  <div class="gE"><span class="gD" email="billing@407-etr-pay.top">Toll Services</span>
    <span style="color:#5f6368;"> &lt;billing@407-etr-pay.top&gt;</span></div>
  <div class="ii gt"><div class="a3s aiL" style="margin-top:16px;line-height:1.6;">
    407 ETR: You have an unpaid toll balance of $42.17. To avoid additional fees,
    pay now at <a href="https://407-etr-pay.top/billing">https://407-etr-pay.top/billing</a>.
    Failure to pay may result in collection action.
  </div></div></body></html>`;

mkdirSync(OUT_DIR, { recursive: true });
const { server, port } = await startStaticServer(ROOT);
const fx = (name) => `http://localhost:${port}/test/${name}`;

const userDataDir = mkdtempSync(join(tmpdir(), 'css-shots-'));
const context = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  executablePath: resolveChromeBinary(),
  chromiumSandbox: false,
  args: [
    `--disable-extensions-except=${ROOT}`,
    `--load-extension=${ROOT}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--no-sandbox',
  ],
});

try {
  const sw = await getSW(context);
  const extensionId = new URL(sw.url()).host;

  // Deterministic baseline; Pro active so the settings shot shows every section.
  await sw.evaluate(async () => {
    await chrome.storage.local.clear();
    await chrome.storage.sync.clear();
    await chrome.storage.sync.set({
      language: 'en', sensitivity: 'balanced',
      proStatus: 'active', proCheckedAt: new Date().toISOString(),
      mailScanEnabled: true,
    });
  });

  // Close the auto-opened onboarding tab so it can't steal focus.
  for (const p of context.pages()) {
    if (/onboarding\/onboarding\.html/.test(p.url())) await p.close();
  }

  await context.route(/https:\/\/cra-refund-2026\.xyz\/.*/, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html><body></body></html>' }));
  await context.route(/https:\/\/mail\.google\.com\/.*/, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: GMAIL_SCAM }));

  const shoot = async (page, name) => {
    await page.screenshot({ path: join(OUT_DIR, name) });
    console.log('wrote', join('docs', 'store-assets', name));
  };

  // ── 1. Full-page warning on a look-alike CRA site ──────────────────────────
  {
    const page = await context.newPage();
    await page.setViewportSize(SIZE);
    await page.goto('https://cra-refund-2026.xyz/claim', { waitUntil: 'load' }).catch(() => {});
    await waitFor(() => /warning\.html/.test(page.url()));
    await sleep(500); // let fonts/rendering settle
    await shoot(page, 'screenshot-1-warning.png');
    await page.close();
  }

  // ── 2. In-page banner on a medium-risk page (reasons expanded) ─────────────
  {
    const page = await context.newPage();
    await page.setViewportSize(SIZE);
    await page.goto(fx('medium-test-page.html'), { waitUntil: 'load' });
    await page.waitForSelector('#css-scam-banner', { timeout: 10000 });
    await page.click('.css-scam-banner__btn--why');
    await page.waitForSelector('#css-scam-banner-reasons:not([hidden])');
    await sleep(300);
    await shoot(page, 'screenshot-2-banner.png');
    await page.close();
  }

  // ── 3. Popup "Check a message" with a flagged email ─────────────────────────
  {
    const page = await context.newPage();
    await page.setViewportSize(SIZE);
    await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    // Present the popup as a floating card on a neutral backdrop.
    await page.addStyleTag({
      content: `
        html { background: #e8eaed; }
        body { margin: 48px auto !important; box-shadow: 0 8px 40px rgba(0,0,0,.28);
               border-radius: 12px; overflow: hidden; }`,
    });
    await page.click('#tab-check');
    await page.fill('#check-sender', 'refunds.cra@gmail.com');
    await page.fill('#check-textarea',
      'Canada Revenue Agency: your tax refund of $458 is waiting. '
      + 'Pay a small processing fee with a gift card within 24 hours or your refund will be cancelled.');
    await page.click('#check-btn');
    await page.waitForSelector('#check-results:not([hidden])', { timeout: 10000 });
    await sleep(500); // score bar animation
    await shoot(page, 'screenshot-3-message-checker.png');
    await page.close();
  }

  // ── 4. Gmail inline chip on a scam email ───────────────────────────────────
  {
    const page = await context.newPage();
    await page.setViewportSize(SIZE);
    await page.goto('https://mail.google.com/mail/u/0/', { waitUntil: 'load' });
    await page.waitForSelector('#css-mail-chip', { timeout: 15000 });
    await page.click('#css-mail-chip .css-mail-chip__btn'); // expand Why?
    await sleep(400);
    await shoot(page, 'screenshot-4-gmail-chip.png');
    await page.close();
  }

  // ── 5. Settings page ────────────────────────────────────────────────────────
  {
    const page = await context.newPage();
    await page.setViewportSize(SIZE);
    await page.goto(`chrome-extension://${extensionId}/options/options.html`);
    await waitFor(async () => (await page.textContent('#lang-heading')) !== '');
    await sleep(400);
    await shoot(page, 'screenshot-5-settings.png');
    await page.close();
  }
} finally {
  await context.close().catch(() => {});
  server.close();
  rmSync(userDataDir, { recursive: true, force: true });
}

console.log('Done — 5 screenshots in docs/store-assets/');
