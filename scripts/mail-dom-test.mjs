/**
 * scripts/mail-dom-test.mjs
 *
 * DOM-level shakedown of content/mail-scanner.js. We can't run real Chrome or
 * sign into Gmail here, so we build fake Gmail/Outlook DOMs *at their real
 * origins* with jsdom, mock the `chrome` API to route CHECK_MESSAGE through the
 * real Layer 3 engine, execute the actual mail-scanner.js source, and assert
 * that the correct verdict chip is injected.
 *
 * Run: node scripts/mail-dom-test.mjs   (requires: npm install jsdom)
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { JSDOM } from 'jsdom';
import { analyzeMessage } from '../lib/message-analyzer.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const load = (p) => JSON.parse(readFileSync(join(ROOT, 'data', p), 'utf8'));
const patterns = load('scam-sender-patterns.json');
const senderDomains = load('known-sender-domains.json');
const whitelist = load('whitelist.json');
const scannerSrc = readFileSync(join(ROOT, 'content', 'mail-scanner.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (d, c) => { if (c) { pass++; console.log('PASS:', d); } else { fail++; console.log('FAIL:', d); } };

const GMAIL_FIXTURE = `
  <div class="bq9"><h2 class="hP">Your CRA refund is ready</h2></div>
  <div class="gE"><span class="gD" email="refunds.cra@gmail.com">CRA Refund</span></div>
  <div class="ii gt"><div class="a3s aiL">
    Canada Revenue Agency: your tax refund of $458.21 is waiting. Pay a small fee
    with a gift card within 24 hours. <a href="https://cra-refund.xyz/claim">canada.ca</a>
  </div></div>`;

const OUTLOOK_FIXTURE = `
  <div role="main">
    <div role="heading" aria-level="2">Unpaid toll notice</div>
    <span title="billing@toll-pay.top">Toll Services</span>
    <div role="document">
      407 ETR: You have an unpaid toll balance. Pay now at
      <a href="https://407-etr-pay.top/billing">https://407-etr-pay.top/billing</a>
    </div>
  </div>`;

const BENIGN_GMAIL = `
  <div class="bq9"><h2 class="hP">Dinner tonight</h2></div>
  <div class="gE"><span class="gD" email="mom@example.com">Mom</span></div>
  <div class="ii gt"><div class="a3s aiL">Hi sweetie, dinner's at 6. Love you.</div></div>`;

/** Runs mail-scanner.js inside a fresh jsdom at `url` with body `html`. */
async function runScenario(url, html) {
  const dom = new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`, { url });
  const { window } = dom;

  // Mock chrome: storage → enabled; runtime.sendMessage routes by type.
  const chrome = {
    runtime: {
      lastError: undefined,
      sendMessage(msg, cb) {
        if (msg.type === 'GET_I18N') { cb && cb({ lang: 'en', strings: {} }); return; }
        if (msg.type === 'CHECK_MESSAGE') {
          const headers = (msg.sender || msg.subject) ? { from: msg.sender, subject: msg.subject } : null;
          const result = analyzeMessage(msg.rawText || '', { patterns, senderDomains, whitelist, headers });
          cb && cb(result);
          return;
        }
        cb && cb(undefined);
      },
    },
    storage: { sync: { get(def, cb) { cb({ ...def, mailScanEnabled: true }); } } },
  };

  // Expose the globals mail-scanner.js relies on, then execute the real source.
  global.window = window;
  global.document = window.document;
  global.location = window.location;
  global.MutationObserver = window.MutationObserver;
  global.getSelection = () => window.getSelection();
  global.chrome = chrome;
  // eslint-disable-next-line no-eval
  eval(scannerSrc);

  // start() schedules evaluateOpenEmail via setTimeout(…,1200)
  await new Promise((r) => setTimeout(r, 1400));
  return window.document;
}

// --- Gmail: scam email → chip injected with non-safe verdict + a reason ---
{
  const doc = await runScenario('https://mail.google.com/mail/u/0/#inbox', GMAIL_FIXTURE);
  const chip = doc.getElementById('css-mail-chip');
  ok('Gmail scam → chip injected', !!chip);
  ok('Gmail scam → chip is non-safe', chip && /css-mail-chip--(low|medium|high)/.test(chip.className));
  ok('Gmail scam → reasons listed', chip && chip.querySelector('.css-mail-chip__reasons li'));
  ok('Gmail → FAB present', !!doc.getElementById('css-mail-fab'));
}

// --- Outlook: scam email → chip injected ---
{
  const doc = await runScenario('https://outlook.live.com/mail/0/inbox', OUTLOOK_FIXTURE);
  const chip = doc.getElementById('css-mail-chip');
  ok('Outlook scam → chip injected', !!chip);
  ok('Outlook scam → non-safe verdict', chip && /css-mail-chip--(low|medium|high)/.test(chip.className));
}

// --- Gmail: benign email → no chip (stays quiet) ---
{
  const doc = await runScenario('https://mail.google.com/mail/u/0/#inbox', BENIGN_GMAIL);
  ok('Gmail benign → no chip', !doc.getElementById('css-mail-chip'));
  ok('Gmail benign → FAB still present', !!doc.getElementById('css-mail-fab'));
}

console.log(`\nMail DOM results: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
