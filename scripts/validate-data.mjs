/**
 * scripts/validate-data.mjs
 *
 * Schema/shape validation for the bundled data files, the manifest, and i18n
 * parity. Run locally or in CI:  node scripts/validate-data.mjs
 * Exit code 0 = all good, 1 = one or more problems.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'));

let problems = 0;
const fail = (m) => { problems++; console.log('✗', m); };
const okMsg = (m) => console.log('✓', m);

const isStr = (v) => typeof v === 'string' && v.length > 0;
const isArr = (v) => Array.isArray(v);

// --- manifest ---
try {
  const m = read('manifest.json');
  if (m.manifest_version !== 3) fail('manifest_version must be 3');
  if (!isStr(m.name) || !isStr(m.version)) fail('manifest missing name/version');
  if (!/^\d+\.\d+\.\d+$/.test(m.version)) fail(`manifest version not semver: ${m.version}`);
  okMsg(`manifest.json v${m.version}`);
} catch (e) { fail('manifest.json: ' + e.message); }

// --- whitelist ---
try {
  const d = read('data/whitelist.json');
  if (!isArr(d.institutions) || d.institutions.length === 0) fail('whitelist has no institutions');
  let bad = 0;
  for (const i of d.institutions || []) {
    if (!isStr(i.domain) || !i.domain.includes('.') || !isStr(i.name) || typeof i.high_value !== 'boolean') bad++;
  }
  if (bad) fail(`whitelist: ${bad} malformed institution entries`);
  else okMsg(`whitelist.json: ${d.institutions.length} institutions`);
} catch (e) { fail('whitelist.json: ' + e.message); }

// --- scam-sender-patterns ---
try {
  const d = read('data/scam-sender-patterns.json');
  if (!isArr(d.rules) || d.rules.length === 0) fail('patterns has no rules');
  let bad = 0, noFr = 0;
  for (const r of d.rules || []) {
    if (!isStr(r.id) || typeof r.weight !== 'number' || typeof r.match !== 'object' || !isStr(r.user_explanation)) bad++;
    if (!isStr(r.user_explanation_fr)) noFr++;
  }
  if (bad) fail(`patterns: ${bad} malformed rules`);
  if (noFr) fail(`patterns: ${noFr} rules missing user_explanation_fr`);
  if (!bad && !noFr) okMsg(`scam-sender-patterns.json: ${d.rules.length} rules (all bilingual)`);
} catch (e) { fail('scam-sender-patterns.json: ' + e.message); }

// --- known-sender-domains ---
try {
  const d = read('data/known-sender-domains.json');
  if (!isArr(d.organizations) || d.organizations.length === 0) fail('sender-domains has no organizations');
  let bad = 0;
  for (const o of d.organizations || []) {
    if (!isStr(o.id) || !isStr(o.name) || !isArr(o.aliases) || !isArr(o.sending_domains)) bad++;
  }
  if (bad) fail(`sender-domains: ${bad} malformed orgs`);
  else okMsg(`known-sender-domains.json: ${d.organizations.length} orgs`);
} catch (e) { fail('known-sender-domains.json: ' + e.message); }

// --- scam-keywords ---
try {
  const d = read('data/scam-keywords.json');
  const c = d.categories || {};
  for (const cat of ['impersonation_terms', 'urgency_triggers', 'payment_red_flags']) {
    const def = c[cat];
    if (!def || typeof def.weight !== 'number' || !isArr(def.terms) || !isArr(def.terms_fr)) fail(`keywords.${cat} malformed`);
  }
  const cred = c.credential_harvesting;
  if (!cred || !isArr(cred.sin_terms) || !isArr(cred.cvv_terms) || !isArr(cred.gov_suffixes)) fail('keywords.credential_harvesting malformed');
  if (problems === 0 || c.impersonation_terms) okMsg('scam-keywords.json: categories present');
} catch (e) { fail('scam-keywords.json: ' + e.message); }

// --- known-bad ---
try {
  const d = read('data/known-bad.json');
  if (!isArr(d.domains)) fail('known-bad.domains must be an array');
  else if (!d.domains.every(isStr)) fail('known-bad.domains has non-string entries');
  else okMsg(`known-bad.json: ${d.domains.length} hostnames`);
} catch (e) { fail('known-bad.json: ' + e.message); }

// --- i18n parity ---
try {
  const mod = await import('../lib/i18n.js');
  const en = Object.keys(mod.strings.en);
  const fr = Object.keys(mod.strings.fr);
  const missing = en.filter((k) => !fr.includes(k));
  const extra = fr.filter((k) => !en.includes(k));
  if (missing.length) fail(`i18n: fr missing keys: ${missing.join(', ')}`);
  if (extra.length) fail(`i18n: fr has extra keys: ${extra.join(', ')}`);
  if (!missing.length && !extra.length) okMsg(`i18n: ${en.length} keys, EN/FR parity`);
} catch (e) { fail('i18n: ' + e.message); }

console.log(`\nvalidate-data: ${problems === 0 ? 'OK' : problems + ' problem(s)'}`);
process.exit(problems > 0 ? 1 : 0);
