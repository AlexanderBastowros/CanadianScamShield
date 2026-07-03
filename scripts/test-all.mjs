/**
 * scripts/test-all.mjs
 *
 * One entry point that runs every test suite in sequence and aggregates the
 * results into a machine-readable summary an automated agent (or CI) can parse:
 *
 *   validate-data  → smoke-test  → mail-dom  → e2e
 *
 * Each child suite follows the shared convention: it prints `PASS:` / `FAIL:`
 * lines and exits 0 (pass) / 1 (failures) / 2 (setup problem, e.g. a missing
 * dependency or browser — NOT a code failure).
 *
 * Stages whose prerequisites are absent are reported as `skipped-setup` with a
 * remediation hint instead of a phantom failure, so the loop fixes the
 * environment rather than chasing a non-bug.
 *
 * Output ends with a delimited JSON block:
 *   ===CSS_TEST_SUMMARY===
 *   { ... }
 *   ===END_CSS_TEST_SUMMARY===
 *
 * Exit code: 1 if any stage actually FAILED, else 0.
 * Run: node scripts/test-all.mjs
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const has = (mod) => existsSync(join(ROOT, 'node_modules', mod, 'package.json'));

/** @type {{id:string, script:string, precheck?:()=>({ok:boolean, hint?:string})}[]} */
const STAGES = [
  { id: 'validate-data', script: 'scripts/validate-data.mjs' },
  { id: 'smoke-test', script: 'scripts/smoke-test.mjs' },
  {
    id: 'mail-dom',
    script: 'scripts/mail-dom-test.mjs',
    precheck: () => has('jsdom')
      ? { ok: true }
      : { ok: false, hint: 'npm install' },
  },
  {
    id: 'e2e',
    script: 'scripts/e2e.mjs',
    precheck: () => has('playwright')
      ? { ok: true }
      : { ok: false, hint: 'npm install && npx playwright install chromium' },
  },
];

const results = [];

for (const stage of STAGES) {
  console.log(`\n===== ${stage.id} =====`);

  if (stage.precheck) {
    const pc = stage.precheck();
    if (!pc.ok) {
      console.log(`SETUP: prerequisites missing for ${stage.id}.`);
      console.log(`       run: ${pc.hint}`);
      results.push({ id: stage.id, status: 'skipped-setup', pass: 0, fail: 0, reason: 'prerequisites missing', hint: pc.hint, failures: [] });
      continue;
    }
  }

  const r = spawnSync(process.execPath, [join(ROOT, stage.script)], {
    cwd: ROOT,
    encoding: 'utf8',
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
  });

  const out = (r.stdout || '') + (r.stderr || '');
  process.stdout.write(out);

  const lines = out.split('\n');
  // Most suites use PASS:/FAIL:; validate-data.mjs uses ✓/✗ — count both.
  const passCount = lines.filter((l) => l.startsWith('PASS:') || l.startsWith('✓')).length;
  const failLines = lines
    .filter((l) => l.startsWith('FAIL:') || l.startsWith('✗'))
    .map((l) => l.replace(/^(FAIL:|✗)\s*/, '').trim());
  const setupHint = (lines.find((l) => l.trim().startsWith('run:')) || '').replace(/^.*run:\s*/, '').trim();

  let status;
  if (r.status === 2) status = 'skipped-setup';
  else if (r.status === 0 && failLines.length === 0) status = 'pass';
  else status = 'fail';

  results.push({
    id: stage.id,
    status,
    pass: passCount,
    fail: failLines.length,
    exit: r.status,
    failures: failLines,
    ...(status === 'skipped-setup' && setupHint ? { hint: setupHint } : {}),
  });
}

// ---------------------------------------------------------------------------
// Aggregate + machine-readable summary
// ---------------------------------------------------------------------------
const totals = results.reduce(
  (acc, s) => ({ pass: acc.pass + s.pass, fail: acc.fail + s.fail }),
  { pass: 0, fail: 0 },
);
const anyFailed = results.some((s) => s.status === 'fail');
const anySkipped = results.some((s) => s.status === 'skipped-setup');
const summary = { ok: !anyFailed, stages: results, totals };

console.log('\n===== summary =====');
for (const s of results) {
  const detail = s.status === 'skipped-setup' ? ` (run: ${s.hint || 'see above'})` : ` — ${s.pass} passed, ${s.fail} failed`;
  console.log(`  ${s.status.toUpperCase().padEnd(13)} ${s.id}${detail}`);
}
console.log(`\nTotals: ${totals.pass} passed, ${totals.fail} failed${anySkipped ? ' (some stages skipped — see hints)' : ''}`);

console.log('\n===CSS_TEST_SUMMARY===');
console.log(JSON.stringify(summary));
console.log('===END_CSS_TEST_SUMMARY===');

process.exit(anyFailed ? 1 : 0);
