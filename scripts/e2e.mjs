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

/**
 * Serves fake HTML for a real https:// host via request interception, so
 * Layer 1 (which keys off the hostname) can be exercised without the network.
 * `handler` is an HTML string or (url) => html.
 */
function routeHtml(context, pattern, handler) {
  return context.route(pattern, (route) => {
    const html = typeof handler === 'function' ? handler(route.request().url()) : handler;
    route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
  });
}

/**
 * Opens popup.html pretending `tabUrl` is the active tab. popup.js resolves
 * the tab to analyse via chrome.tabs.query — opened as a normal page the popup
 * itself would be the active tab, so stub the query before its script runs.
 */
async function openPopupWithActiveTab(context, extensionId, tabUrl) {
  const popup = await context.newPage();
  await popup.addInitScript((u) => {
    chrome.tabs.query = () => Promise.resolve([{ id: 999, url: u }]);
  }, tabUrl);
  await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  return popup;
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

  // ---- Case 0: first install opens the onboarding page ----------------------
  {
    const onboarding = await waitFor(
      () => context.pages().find((p) => /onboarding\/onboarding\.html/.test(p.url())),
      { timeout: 10000 },
    );
    ok('install → onboarding page opened automatically', !!onboarding);
    if (onboarding) await onboarding.close();
  }

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

  // ---- Case 4b: permissive sensitivity downgrades a low page to silent ------
  {
    await reset(context, { sensitivity: 'permissive' });
    const page = await context.newPage();
    const url = fx('low-test-page.html');
    await page.goto(url, { waitUntil: 'load' });
    await sleep(3000); // past the idle-callback window
    ok('permissive → low page shows no badge', (await badgeFor(context, url)) === '');
    ok('permissive → low page not redirected', !/warning\.html/.test(page.url()));
    await page.close();
  }

  // ---- Case 4c: strict sensitivity escalates a medium page to full block ----
  {
    await reset(context, { sensitivity: 'strict' });
    const page = await context.newPage();
    await page.goto(fx('medium-test-page.html'), { waitUntil: 'load' }).catch(() => {});
    const redirected = await waitFor(() => /warning\.html/.test(page.url()), { timeout: 10000 });
    ok('strict → medium page escalates to full-page warning', redirected);
    await page.close();
  }

  // ---- Case 4d: banner renders in French when language is fr ----------------
  {
    await reset(context, { language: 'fr' });
    const page = await context.newPage();
    await page.goto(fx('medium-test-page.html'), { waitUntil: 'load' });
    const banner = await waitFor(async () => (await page.$('#css-scam-banner')) ? true : false, { timeout: 10000 });
    ok('fr → banner injected', banner);
    if (banner) {
      const text = await page.textContent('#css-scam-banner .css-scam-banner__message');
      ok('fr → banner message is French', /ce site semble suspect/i.test(text || ''));
    }
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

  // ==========================================================================
  // Part 2 — full scenario coverage (routed https hosts, popup states, banner
  // interactions, options deep-dive, webmail via request interception)
  // ==========================================================================

  const BENIGN_HTML = '<!doctype html><html><head><title>Site</title></head><body><p>Plain page.</p></body></html>';
  await routeHtml(context, /https:\/\/(www\.)?canada\.ca\/.*/, BENIGN_HTML);
  await routeHtml(context, /https:\/\/cra-refund-2026\.xyz\/.*/, BENIGN_HTML);
  await context.route(/https:\/\/github\.com\/.*/, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html><body>gh</body></html>' }));
  await context.route(/https:\/\/raw\.githubusercontent\.com\/.*/, (route) =>
    route.fulfill({ status: 404, body: 'not found' }));

  // ---- Case 14: whitelisted institution (Layer 1) → silent, badge cleared ---
  {
    await reset(context);
    const page = await context.newPage();
    const url = 'https://www.canada.ca/en.html';
    await page.goto(url, { waitUntil: 'load' });
    await sleep(2500);
    ok('canada.ca (routed) → no banner, no redirect', !(await page.$('#css-scam-banner')) && page.url() === url);
    ok('canada.ca (routed) → badge cleared', (await badgeFor(context, url)) === '');
    await page.close();
  }

  // ---- Case 15: pure Layer-1 high (fake-gov keyword + bad TLD) → blocked ----
  {
    await reset(context);
    const page = await context.newPage();
    const url = 'https://cra-refund-2026.xyz/claim';
    await page.goto(url, { waitUntil: 'load' }).catch(() => {});
    const redirected = await waitFor(() => /warning\.html/.test(page.url()), { timeout: 10000 });
    ok('cra-refund-2026.xyz → blocked by Layer 1 alone', redirected);

    // ---- Case 16: warning page renders the details -------------------------
    if (redirected) {
      const shownUrl = await page.textContent('#suspicious-url');
      ok('warning page shows the suspicious URL', shownUrl === url);
      const reasonCount = await page.$$eval('#reasons-list li', (els) => els.length);
      ok('warning page lists at least one reason', reasonCount >= 1);
      ok('warning page buttons are labeled',
        !!(await page.textContent('#btn-go-back')) && !!(await page.textContent('#btn-proceed')));

      // ---- Case 17: "Report a mistake" opens a prefilled GitHub issue ------
      // The SW opens the tab via chrome.tabs.create, whose navigation races
      // ahead of Playwright's route interception — capture the URL at the
      // source instead of depending on the network.
      await sw.evaluate(() => {
        self._origTabsCreate = chrome.tabs.create;
        self._createdUrls = [];
        chrome.tabs.create = (opts) => {
          self._createdUrls.push(opts && opts.url);
          return Promise.resolve({});
        };
      });
      await page.click('#report-fp');
      const issueUrl = await waitFor(
        () => sw.evaluate(() => (self._createdUrls || [])[0] || false),
        { timeout: 8000 },
      );
      await sw.evaluate(() => { chrome.tabs.create = self._origTabsCreate; });
      ok('report-a-mistake → opens github issue with false-positive label',
        /github\.com\/.+\/issues\/new\?.*false-positive/.test(issueUrl || ''));
    }
    await page.close();
  }

  // ---- Case 18: popup status states (active tab stubbed) --------------------
  {
    await reset(context);

    // Unknown: opened as a plain page, the popup itself is the active tab.
    const unknown = await context.newPage();
    await unknown.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await unknown.waitForSelector('#status-result:not([hidden])', { timeout: 8000 });
    ok('popup (extension page active) → unknown state',
      /status-text--unknown/.test(await unknown.getAttribute('#status-text', 'class') || ''));
    await unknown.close();

    // Safe: whitelisted institution, with the recognized-as detail line.
    const safe = await openPopupWithActiveTab(context, extensionId, 'https://www.canada.ca/en.html');
    await safe.waitForSelector('#status-result:not([hidden])', { timeout: 8000 });
    ok('popup over canada.ca → safe state',
      /status-text--safe/.test(await safe.getAttribute('#status-text', 'class') || ''));
    ok('popup over canada.ca → recognized as Government of Canada',
      /Government of Canada/.test(await safe.textContent('#status-detail') || ''));
    await safe.close();

    // Caution: suspicious TLD alone scores low.
    const caution = await openPopupWithActiveTab(context, extensionId, 'https://portal-notice.xyz/');
    await caution.waitForSelector('#status-result:not([hidden])', { timeout: 8000 });
    ok('popup over .xyz site → caution state',
      /status-text--caution/.test(await caution.getAttribute('#status-text', 'class') || ''));
    await caution.close();

    // Flagged: Layer-1 high, and the Why? accordion reveals reasons.
    const flagged = await openPopupWithActiveTab(context, extensionId, 'https://cra-refund-2026.xyz/claim');
    await flagged.waitForSelector('#status-result:not([hidden])', { timeout: 8000 });
    ok('popup over flagged site → flagged state',
      /status-text--flagged/.test(await flagged.getAttribute('#status-text', 'class') || ''));
    await flagged.click('#why-btn');
    await flagged.waitForSelector('#reasons-panel:not([hidden])', { timeout: 5000 });
    const whyCount = await flagged.$$eval('#reasons-list li', (els) => els.length);
    ok('popup Why? accordion reveals reasons', whyCount >= 1);
    await flagged.close();
  }

  // ---- Case 19: popup checker — empty input error + Ctrl+Enter shortcut -----
  {
    await reset(context);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.click('#tab-check');
    await popup.click('#check-btn');
    await popup.waitForSelector('#check-error:not([hidden])', { timeout: 5000 });
    ok('popup checker empty input → error shown', true);
    ok('popup checker empty input → results stay hidden',
      await popup.$eval('#check-results', (el) => el.hidden));

    await popup.fill('#check-textarea', "Hi mom, dinner at 6 tonight.");
    await popup.press('#check-textarea', 'Control+Enter');
    await popup.waitForSelector('#check-results:not([hidden])', { timeout: 8000 });
    ok('popup checker Ctrl+Enter → runs the check',
      /check-verdict--safe/.test(await popup.getAttribute('#check-verdict', 'class') || ''));
    await popup.close();
  }

  // ---- Case 20: popup renders in French ------------------------------------
  {
    await reset(context, { language: 'fr' });
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    const tabLabel = await waitFor(async () => {
      const t = await popup.textContent('#tab-status');
      return t === 'Ce site' ? t : false;
    }, { timeout: 5000 });
    ok('popup (language fr) → tabs labeled in French', tabLabel === 'Ce site');
    await popup.close();
  }

  // ---- Case 21: banner component — reasons, official link, dismiss ----------
  // Drive the content script directly (SW → tabs.sendMessage) so every banner
  // affordance can be asserted deterministically.
  {
    await reset(context);
    const page = await context.newPage();
    const url = fx('benign-test-page.html');
    await page.goto(url, { waitUntil: 'load' });

    const send = () => sw.evaluate(async (u) => {
      const [tab] = await chrome.tabs.query({ url: u });
      await chrome.tabs.sendMessage(tab.id, {
        type: 'SHOW_BANNER', level: 'medium',
        reasons: ['Test reason one', 'Test reason two'],
        officialUrl: 'https://www.canada.ca',
      });
    }, url);

    await send();
    await page.waitForSelector('#css-scam-banner', { timeout: 8000 });
    ok('banner (driven) → first reason shown',
      (await page.textContent('#css-scam-banner .css-scam-banner__first-reason')) === 'Test reason one');

    ok('banner Why? starts collapsed',
      (await page.getAttribute('.css-scam-banner__btn--why', 'aria-expanded')) === 'false');
    await page.click('.css-scam-banner__btn--why');
    await page.waitForSelector('#css-scam-banner-reasons:not([hidden])', { timeout: 5000 });
    const liCount = await page.$$eval('#css-scam-banner-reasons li', (els) => els.length);
    ok('banner Why? expands the full reasons list', liCount === 2);
    ok('banner official-site link points at the real site',
      /^https:\/\/www\.canada\.ca\/?$/.test(await page.getAttribute('#css-scam-banner-reasons a', 'href') || ''));

    await send(); // idempotency: a second SHOW_BANNER must not duplicate
    await sleep(500);
    const bannerCount = await page.$$eval('.css-scam-banner', (els) => els.length);
    ok('banner is idempotent (no duplicates)', bannerCount === 1);

    await page.click('.css-scam-banner__btn--dismiss');
    await sleep(300);
    ok('banner Dismiss removes it', !(await page.$('#css-scam-banner')));
    await page.close();
  }

  // ---- Case 22: options — validation, duplicates, remove, Pro lock ----------
  {
    await reset(context);
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);

    await opts.fill('#whitelist-input', 'not a domain!!');
    await opts.click('#whitelist-add-btn');
    await opts.waitForSelector('#whitelist-error:not([hidden])', { timeout: 5000 });
    ok('options invalid domain → error shown', true);

    await opts.fill('#whitelist-input', 'example.com');
    await opts.click('#whitelist-add-btn');
    await opts.waitForSelector('#whitelist-list .domain-list__item', { timeout: 5000 });
    await opts.fill('#whitelist-input', 'example.com');
    await opts.click('#whitelist-add-btn');
    await opts.waitForSelector('#whitelist-error:not([hidden])', { timeout: 5000 });
    ok('options duplicate domain → duplicate error',
      /already/.test(await opts.textContent('#whitelist-error') || ''));

    await opts.click('#whitelist-list .btn--remove');
    const emptied = await waitFor(async () =>
      (await opts.$$eval('#whitelist-list .domain-list__item', (els) => els.length)) === 0, { timeout: 5000 });
    ok('options remove → entry removed from the list', emptied);
    const wl = await sw.evaluate(() => chrome.storage.sync.get({ customWhitelist: [] }).then((r) => r.customWhitelist));
    ok('options remove → storage emptied', Array.isArray(wl) && wl.length === 0);

    ok('options free tier → Pro sensitivity radios locked',
      await opts.isDisabled('input[name="sensitivity"][value="strict"]'));
    ok('options free tier → Pro blocklist input locked', await opts.isDisabled('#blocklist-input'));
    await opts.close();
  }

  // ---- Case 23: options Pro — blocklist add + PhishTank opt-in ---------------
  {
    await reset(context, { proStatus: 'active', proCheckedAt: new Date().toISOString() });
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);
    const unlocked = await waitFor(async () => !(await opts.isDisabled('#blocklist-input')), { timeout: 6000 });
    ok('options Pro → blocklist unlocked', unlocked);

    await opts.fill('#blocklist-input', 'bad-site.com');
    await opts.click('#blocklist-add-btn');
    const persisted = await waitFor(async () => {
      const r = await sw.evaluate(() => chrome.storage.sync.get({ customBlocklist: [] }).then((x) => x.customBlocklist));
      return r.includes('bad-site.com');
    }, { timeout: 5000 });
    ok('options Pro → blocklist entry persisted', persisted);

    await opts.check('#phishtank-toggle');
    const optIn = await waitFor(async () =>
      sw.evaluate(() => chrome.storage.sync.get({ phishtankOptIn: false }).then((r) => r.phishtankOptIn)), { timeout: 5000 });
    ok('options Pro → PhishTank opt-in persisted', optIn === true);
    await opts.close();
  }

  // ---- Case 24: options in French + manual data update ----------------------
  {
    await reset(context, { language: 'fr' });
    const opts = await context.newPage();
    await opts.goto(`chrome-extension://${extensionId}/options/options.html`);
    const heading = await waitFor(async () => {
      const t = await opts.textContent('#lang-heading');
      return t === 'Langue' ? t : false;
    }, { timeout: 5000 });
    ok('options (language fr) → headings in French', heading === 'Langue');

    // "Update now" with the data host unreachable (routed 404) must still
    // complete gracefully and stamp a last-updated time.
    await opts.click('#update-now-btn');
    const stamped = await waitFor(async () => {
      const t = await opts.textContent('#data-updated-value');
      return !!t && t.trim() !== '—';
    }, { timeout: 10000 });
    ok('options Update now (data host down) → completes and stamps a date', stamped);
    await opts.close();
  }

  // ---- Case 25: Gmail webmail chip via request interception ------------------
  const GMAIL_SCAM = `<!doctype html><html><body>
    <div class="bq9"><h2 class="hP">Unpaid toll notice</h2></div>
    <div class="gE"><span class="gD" email="billing@407-etr-pay.top">Toll Services</span></div>
    <div class="ii gt"><div class="a3s aiL">
      407 ETR: You have an unpaid toll balance. Pay now at
      <a href="https://407-etr-pay.top/billing">https://407-etr-pay.top/billing</a>
    </div></div></body></html>`;
  const GMAIL_BENIGN = `<!doctype html><html><body>
    <div class="bq9"><h2 class="hP">Dinner tonight</h2></div>
    <div class="gE"><span class="gD" email="mom@example.com">Mom</span></div>
    <div class="ii gt"><div class="a3s aiL">Hi sweetie, dinner's at 6. Love you.</div></div></body></html>`;
  await routeHtml(context, /https:\/\/mail\.google\.com\/.*/, (u) =>
    u.includes('/u/1/') ? GMAIL_BENIGN : GMAIL_SCAM);
  await routeHtml(context, /https:\/\/outlook\.live\.com\/.*/, `<!doctype html><html><body>
    <div role="main">
      <div role="heading" aria-level="2">Unpaid toll notice</div>
      <span title="billing@toll-pay.top">Toll Services</span>
      <div role="document">407 ETR: You have an unpaid toll balance. Pay now at
        <a href="https://407-etr-pay.top/billing">https://407-etr-pay.top/billing</a></div>
    </div></body></html>`);

  {
    await reset(context);
    const page = await context.newPage();
    await page.goto('https://mail.google.com/mail/u/0/', { waitUntil: 'load' });
    const chip = await page.waitForSelector('#css-mail-chip', { timeout: 12000 }).catch(() => null);
    ok('Gmail (routed) scam email → verdict chip injected', !!chip);
    if (chip) {
      ok('Gmail chip → non-safe verdict',
        /css-mail-chip--(low|medium|high)/.test(await page.getAttribute('#css-mail-chip', 'class') || ''));
      const reasonCount = await page.$$eval('#css-mail-chip-reasons li', (els) => els.length).catch(() => 0);
      await page.click('#css-mail-chip .css-mail-chip__btn').catch(() => {});
      ok('Gmail chip → lists at least one reason', reasonCount >= 1);
    }
    ok('Gmail → scan FAB present', !!(await page.$('#css-mail-fab')));
    await page.close();
  }

  // ---- Case 26: Gmail benign email → chip stays away -------------------------
  {
    await reset(context);
    const page = await context.newPage();
    await page.goto('https://mail.google.com/mail/u/1/', { waitUntil: 'load' });
    await sleep(3500); // past the scanner's 1200ms initial pass + debounce
    ok('Gmail benign email → no chip', !(await page.$('#css-mail-chip')));
    ok('Gmail benign email → FAB still present', !!(await page.$('#css-mail-fab')));
    await page.close();
  }

  // ---- Case 27: mail scanning disabled → scanner fully inert -----------------
  {
    await reset(context, { mailScanEnabled: false });
    const page = await context.newPage();
    await page.goto('https://mail.google.com/mail/u/0/', { waitUntil: 'load' });
    await sleep(3500);
    ok('mail scan disabled → no chip', !(await page.$('#css-mail-chip')));
    ok('mail scan disabled → no FAB', !(await page.$('#css-mail-fab')));
    await page.close();
  }

  // ---- Case 28: Outlook webmail chip -----------------------------------------
  {
    await reset(context);
    const page = await context.newPage();
    await page.goto('https://outlook.live.com/mail/0/', { waitUntil: 'load' });
    const chip = await page.waitForSelector('#css-mail-chip', { timeout: 12000 }).catch(() => null);
    ok('Outlook (routed) scam email → verdict chip injected', !!chip);
    if (chip) {
      ok('Outlook chip → non-safe verdict',
        /css-mail-chip--(low|medium|high)/.test(await page.getAttribute('#css-mail-chip', 'class') || ''));
    }
    await page.close();
  }

  // ---- Case 29: custom blocklist blocks navigation with the user's reason ----
  {
    await reset(context, { customBlocklist: ['localhost'] });
    const page = await context.newPage();
    await page.goto(fx('benign-test-page.html'), { waitUntil: 'load' }).catch(() => {});
    const redirected = await waitFor(() => /warning\.html/.test(page.url()), { timeout: 10000 });
    ok('custom blocklist → navigation blocked with full-page warning', redirected);
    if (redirected) {
      const reasons = await page.$$eval('#reasons-list li', (els) => els.map((e) => e.textContent));
      ok('custom blocklist → warning explains "Blocked by your settings"',
        reasons.some((r) => /Blocked by your settings/.test(r)));
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
