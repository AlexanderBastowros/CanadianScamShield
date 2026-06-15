/**
 * scripts/e2e.mjs
 *
 * Real-browser end-to-end tests for the Canadian Scam Shield MV3 extension.
 * Loads the UNPACKED extension into a headed Chromium under Xvfb (MV3 service
 * workers + content scripts do not load in Playwright's default headless), then
 * drives the actual surfaces a user touches:
 *   • navigation verdicts (full-page warning / banner / badge / safe)
 *   • the popup message checker + GET_STATUS messaging route
 *   • the options page (whitelist, mail-scan, Pro sensitivity) + storage persistence
 *   • the warning page "Continue anyway" / "Go back to safety" flows
 *
 * Same convention as scripts/smoke-test.mjs: prints PASS:/FAIL: lines and exits
 *   0 = all pass
 *   1 = one or more test failures
 *   2 = setup problem (missing dependency / browser) — NOT a code failure
 *
 * Run: node scripts/e2e.mjs        (auto re-execs under xvfb-run if no DISPLAY)
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, rmSync, createReadStream, statSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import http from 'node:http';

const SELF = fileURLToPath(import.meta.url);
const ROOT = join(dirname(SELF), '..');

// ---------------------------------------------------------------------------
// 0. Re-exec under Xvfb when there is no X display.
//    A headed browser (required for MV3 extensions) needs a display; this box
//    is a headless server but ships xvfb-run. Guard with CSS_XVFB to avoid an
//    infinite re-exec loop.
// ---------------------------------------------------------------------------
if (!process.env.DISPLAY && !process.env.CSS_XVFB) {
  const hasXvfb = spawnSync('sh', ['-c', 'command -v xvfb-run'], { stdio: 'ignore' }).status === 0;
  if (hasXvfb) {
    const r = spawnSync('xvfb-run', ['-a', process.execPath, SELF], {
      stdio: 'inherit',
      env: { ...process.env, CSS_XVFB: '1' },
    });
    process.exit(r.status ?? 1);
  }
  // No xvfb-run and no display — let it proceed; launch will fail with a clear
  // setup error we translate into exit code 2 below.
}

// ---------------------------------------------------------------------------
// 1. Load Playwright (treat a missing module as a setup problem, not a failure)
// ---------------------------------------------------------------------------
let chromium;
try {
  ({ chromium } = await import('playwright'));
} catch {
  console.log('SETUP: playwright is not installed.');
  console.log('       run: npm install  &&  npx playwright install chromium');
  process.exit(2);
}

// ---------------------------------------------------------------------------
// 2. Tiny assert + wait helpers (mirror smoke-test.mjs style)
// ---------------------------------------------------------------------------
let pass = 0, fail = 0;
function ok(desc, cond) {
  if (cond) { pass++; console.log('PASS:', desc); }
  else { fail++; console.log('FAIL:', desc); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Polls fn() until it returns truthy or the timeout elapses. */
async function waitFor(fn, { timeout = 9000, interval = 150 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try { const v = await fn(); if (v) return v; } catch { /* keep polling */ }
    await sleep(interval);
  }
  return false;
}

// ---------------------------------------------------------------------------
// 3. Static fixture server (serves the repo root over http://127.0.0.1:<port>)
// ---------------------------------------------------------------------------
const MIME = { html: 'text/html', js: 'text/javascript', css: 'text/css', json: 'application/json', png: 'image/png' };

function startStaticServer(root) {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent((req.url || '/').split('?')[0]).replace(/^(\.\.[/\\])+/, '');
    const file = join(root, rel);
    try {
      if (statSync(file).isFile()) {
        const ext = file.split('.').pop();
        res.setHeader('Content-Type', MIME[ext] || 'text/plain; charset=utf-8');
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

// ---------------------------------------------------------------------------
// 4. Service-worker access (re-acquire on demand; MV3 SWs can be evicted)
// ---------------------------------------------------------------------------
async function getSW(context) {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
  // The extension APIs (chrome.storage / chrome.tabs) are injected into a freshly
  // started MV3 worker asynchronously — poll until they're live before returning.
  await waitFor(async () => {
    try { return await sw.evaluate(() => !!(globalThis.chrome && chrome.storage && chrome.tabs && chrome.action)); }
    catch { return false; }
  }, { timeout: 10000, interval: 100 });
  return sw;
}

/** Deterministic baseline state before each test. Pass extra to override. */
async function reset(context, extra = {}) {
  const sw = await getSW(context);
  await sw.evaluate(async (over) => {
    await chrome.storage.local.clear();
    try { await chrome.storage.session.set({ _overrides: {} }); } catch { /* ignore */ }
    await chrome.storage.sync.clear();
    await chrome.storage.sync.set(Object.assign({
      language: 'en',
      sensitivity: 'balanced',
      customWhitelist: [],
      customBlocklist: [],
      proStatus: 'none',
      mailScanEnabled: true,
      phishtankOptIn: false,
    }, over));
  }, extra);
}

/** Reads the toolbar badge text for the tab whose URL matches `url`. */
async function badgeFor(context, url) {
  const sw = await getSW(context);
  return sw.evaluate(async (u) => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find((t) => t.url === u);
    return tab ? chrome.action.getBadgeText({ tabId: tab.id }) : '__notab__';
  }, url);
}

// ---------------------------------------------------------------------------
// 5. Main
// ---------------------------------------------------------------------------
const { server, port } = await startStaticServer(ROOT);
// Serve via the `localhost` hostname, NOT 127.0.0.1: a raw IP literal scores +40
// in Layer 1 (url-analyzer flags raw IPs), which would bump every fixture up a
// band. `localhost` is treated as an ordinary (score-0) host.
const fx = (name) => `http://localhost:${port}/test/${name}`;

// Locate a Chrome/Chromium binary. Playwright's own browser download host is
// often blocked by network egress policy, so allow an external binary via
// CSS_CHROME_BIN, falling back to a Chrome-for-Testing build under ~/.cache/cft.
function resolveChromeBinary() {
  if (process.env.CSS_CHROME_BIN && existsSync(process.env.CSS_CHROME_BIN)) return process.env.CSS_CHROME_BIN;
  const cft = join(homedir(), '.cache', 'cft', 'chrome-linux64', 'chrome');
  if (existsSync(cft)) return cft;
  return undefined; // let Playwright use its bundled chromium if present
}
const executablePath = resolveChromeBinary();

const userDataDir = mkdtempSync(join(tmpdir(), 'css-e2e-'));
let context;
try {
  context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath,
    chromiumSandbox: false,
    args: [
      `--disable-extensions-except=${ROOT}`,
      `--load-extension=${ROOT}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--no-sandbox',
    ],
  });
} catch (e) {
  const msg = String(e && e.message || e);
  if (/Executable doesn't exist|playwright install|Failed to launch/i.test(msg)) {
    console.log('SETUP: Chromium for Playwright is not installed.');
    console.log('       run: npx playwright install chromium');
    server.close();
    rmSync(userDataDir, { recursive: true, force: true });
    process.exit(2);
  }
  throw e;
}

try {
  const sw = await getSW(context);
  const extensionId = new URL(sw.url()).host;
  ok('extension service worker registered', !!extensionId);

  // Warm the SW once so the first verdict isn't slowed by lazy data loading.
  await reset(context);
  await sw.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_STATUS', url: 'http://127.0.0.1/' }).catch(() => {}));

  // ---- Case 1: scam page → full-page warning redirect ----------------------
  {
    await reset(context);
    const page = await context.newPage();
    await page.goto(fx('scam-test-page.html'), { waitUntil: 'load' }).catch(() => {});
    const redirected = await waitFor(
      () => /chrome-extension:\/\/[a-p]+\/warning\/warning\.html/.test(page.url()),
      { timeout: 10000 },
    );
    ok('scam page → redirected to full-page warning', redirected);
    if (redirected) {
      const u = new URL(page.url());
      ok('warning URL carries the original url param', u.searchParams.get('url') === fx('scam-test-page.html'));
      ok('warning URL carries a numeric score', Number(u.searchParams.get('score')) >= 80);
    }
    await page.close();
  }

  // ---- Case 2: medium page → in-page banner --------------------------------
  {
    await reset(context);
    const page = await context.newPage();
    await page.goto(fx('medium-test-page.html'), { waitUntil: 'load' });
    const banner = await waitFor(async () => (await page.$('#css-scam-banner')) ? true : false, { timeout: 10000 });
    ok('medium page → banner injected (#css-scam-banner)', banner);
    if (banner) {
      const cls = await page.getAttribute('#css-scam-banner', 'class');
      ok('banner carries the --medium modifier', /css-scam-banner--medium/.test(cls || ''));
      ok('banner lists at least one reason', !!(await page.$('#css-scam-banner .css-scam-banner__first-reason')));
    }
    // negative: no full-page redirect for medium
    ok('medium page → not redirected to warning', !/warning\.html/.test(page.url()));
    await page.close();
  }

  // ---- Case 3: low page → badge "!" only -----------------------------------
  {
    await reset(context);
    const page = await context.newPage();
    const url = fx('low-test-page.html');
    await page.goto(url, { waitUntil: 'load' });
    const gotBadge = await waitFor(async () => (await badgeFor(context, url)) === '!', { timeout: 10000 });
    ok('low page → toolbar badge shows "!"', gotBadge);
    ok('low page → no banner injected', !(await page.$('#css-scam-banner')));
    ok('low page → not redirected to warning', !/warning\.html/.test(page.url()));
    await page.close();
  }

  // ---- Case 4: benign page → silent (no banner, no redirect, empty badge) ---
  {
    await reset(context);
    const page = await context.newPage();
    const url = fx('benign-test-page.html');
    await page.goto(url, { waitUntil: 'load' });
    // Bounded settle: well past the content script's requestIdleCallback(2000) window.
    await sleep(3000);
    ok('benign page → no banner', !(await page.$('#css-scam-banner')));
    ok('benign page → not redirected to warning', !/warning\.html/.test(page.url()));
    ok('benign page → badge cleared', (await badgeFor(context, url)) === '');
    await page.close();
  }

  // ---- Case 5: popup message checker — scam text → flagged + rules ----------
  {
    await reset(context);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.click('#tab-check');
    await popup.fill('#check-sender', 'refunds.cra@gmail.com');
    await popup.fill('#check-textarea',
      'Canada Revenue Agency: your tax refund of $458 is waiting. Pay a small fee with a gift card within 24 hours.');
    await popup.click('#check-btn');
    await popup.waitForSelector('#check-results:not([hidden])', { timeout: 8000 });
    const verdictCls = await popup.getAttribute('#check-verdict', 'class');
    ok('popup checker (scam) → non-safe verdict', /check-verdict--(low|medium|high)/.test(verdictCls || ''));
    const ruleCount = await popup.$$eval('#check-rules-list li', (els) => els.length);
    ok('popup checker (scam) → at least one fired rule listed', ruleCount >= 1);
    const score = Number(await popup.textContent('#score-value'));
    ok('popup checker (scam) → score > 0', score > 0);
    await popup.close();
  }

  // ---- Case 6: popup message checker — benign text → safe -------------------
  {
    await reset(context);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.click('#tab-check');
    await popup.fill('#check-textarea', "Hi mom, I'll be home for dinner at 6. Love you.");
    await popup.click('#check-btn');
    await popup.waitForSelector('#check-results:not([hidden])', { timeout: 8000 });
    const verdictCls = await popup.getAttribute('#check-verdict', 'class');
    ok('popup checker (benign) → safe verdict', /check-verdict--safe/.test(verdictCls || ''));
    await popup.close();
  }

  // ---- Case 7: options whitelist add → persisted to storage.sync -----------
  {
    await reset(context);
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);
    await opts.fill('#whitelist-input', 'example.com');
    await opts.click('#whitelist-add-btn');
    await opts.waitForSelector('#whitelist-list .domain-list__item', { timeout: 8000 });
    const persisted = await (await getSW(context)).evaluate(
      () => chrome.storage.sync.get({ customWhitelist: [] }).then((r) => r.customWhitelist),
    );
    ok('options whitelist add → persisted to storage.sync', Array.isArray(persisted) && persisted.includes('example.com'));
    await opts.close();
  }

  // ---- Case 8: options mail-scan toggle → persisted ------------------------
  {
    await reset(context);
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);
    // Default is checked (true); wait for that to settle, then toggle off.
    await waitFor(() => opts.isChecked('#mailscan-toggle'), { timeout: 5000 });
    await opts.click('#mailscan-toggle');
    const enabled = await (await getSW(context)).evaluate(
      () => chrome.storage.sync.get({ mailScanEnabled: true }).then((r) => r.mailScanEnabled),
    );
    ok('options mail-scan toggle → mailScanEnabled persisted false', enabled === false);
    await opts.close();
  }

  // ---- Case 9: options sensitivity (Pro) → enabled + persisted -------------
  {
    await reset(context, { proStatus: 'active', proLicense: 'CSS-TEST-TEST-TEST-TEST', proCheckedAt: new Date().toISOString() });
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);
    const strict = 'input[name="sensitivity"][value="strict"]';
    const enabled = await waitFor(async () => (await opts.isDisabled(strict)) === false, { timeout: 6000 });
    ok('options sensitivity (Pro) → radios enabled', enabled);
    await opts.check(strict);
    const sens = await (await getSW(context)).evaluate(
      () => chrome.storage.sync.get({ sensitivity: 'balanced' }).then((r) => r.sensitivity),
    );
    ok('options sensitivity (Pro) → sensitivity persisted "strict"', sens === 'strict');
    await opts.close();
  }

  // ---- Case 10: GET_STATUS route + custom blocklist → high -----------------
  {
    await reset(context, { customBlocklist: ['localhost'] });
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    const res = await popup.evaluate(
      (u) => chrome.runtime.sendMessage({ type: 'GET_STATUS', url: u }),
      fx('benign-test-page.html'),
    );
    ok('GET_STATUS + custom blocklist → verdict high', res && res.verdict === 'high');
    await popup.close();
  }

  // ---- Case 11: custom whitelist beats blocklist (user choice wins) --------
  {
    await reset(context, { customWhitelist: ['localhost'], customBlocklist: ['localhost'] });
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    const res = await popup.evaluate(
      (u) => chrome.runtime.sendMessage({ type: 'GET_STATUS', url: u }),
      fx('scam-test-page.html'),
    );
    ok('GET_STATUS + whitelist precedence → verdict safe', res && res.verdict === 'safe');
    await popup.close();
  }

  // ---- Case 12: warning page → "Continue anyway" overrides the block -------
  {
    await reset(context);
    const page = await context.newPage();
    const target = fx('scam-test-page.html');
    await page.goto(target, { waitUntil: 'load' }).catch(() => {});
    const onWarning = await waitFor(() => /warning\.html/.test(page.url()), { timeout: 10000 });
    ok('continue-anyway: reached warning page', onWarning);
    if (onWarning) {
      await page.click('#btn-proceed');
      const back = await waitFor(() => page.url() === target, { timeout: 10000 });
      ok('continue-anyway: navigated back to the original page', back);
      // It must NOT bounce back to the warning page now that an override is set.
      await sleep(2500);
      ok('continue-anyway: override holds (no re-block)', !/warning\.html/.test(page.url()));
    }
    await page.close();
    await reset(context); // clear the session override so it can't poison later runs
  }

  // ---- Case 13: warning page → "Go back to safety" navigates away ----------
  {
    await reset(context);
    const page = await context.newPage();
    await page.goto(fx('scam-test-page.html'), { waitUntil: 'load' }).catch(() => {});
    const onWarning = await waitFor(() => /warning\.html/.test(page.url()), { timeout: 10000 });
    ok('go-back: reached warning page', onWarning);
    if (onWarning) {
      await page.click('#btn-go-back');
      const left = await waitFor(
        () => /newtab|new-tab|about:blank/.test(page.url()),
        { timeout: 10000 },
      );
      ok('go-back: navigated to a safe page', left);
    }
    await page.close();
  }
} finally {
  if (context) await context.close().catch(() => {});
  server.close();
  rmSync(userDataDir, { recursive: true, force: true });
}

console.log(`\nE2E results: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
