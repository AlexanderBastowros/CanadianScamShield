/**
 * lib/domain-reputation.js
 * Heuristics for spotting throwaway/algorithmically-generated email domains and
 * mailbox names — the kind used by scammers who set up valid SPF/DKIM on a
 * nonsense domain (so it shows as "Trusted Sender" but the address is garbage).
 *
 * Pure ES module — no DOM, no Chrome. Reused by the message analyzer (and
 * available to the URL analyzer).
 *
 * The core idea: real domain labels and mailbox names read like language
 * (pronounceable, common letter pairs). Random strings like "fqwapijmo" or
 * "ihwjsagmmaw" have very few common English bigrams. We score "English-likeness"
 * from a compact common-bigram table and flag labels that score low AND are long
 * enough to judge.
 */

// ~180 of the most common English bigrams. A label made of these reads like a
// word; a random string mostly won't contain them.
const COMMON_BIGRAMS = new Set((
  'th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr ne ui id ge no rt et ng ie pa pl pp ot ad pl pi pl po ti us pl us wa wo we wh wi tr tu su sc sh sp ss si sa ld lo li la le ke ki ki na ne ni no nu mi mo mu ba bo bu bi do du da di du fa fe fi fu ga go gu ga ge gi gr gl ar br cr dr fr pr tr st sp sk sl sm sn sw tw qu ph ch sh th wh ck ng nk mp nt nd ct ft lt rt sk'
).split(' ').filter(Boolean));

/** Lowercases and keeps only a–z. */
function lettersOnly(s) {
  return String(s || '').toLowerCase().replace(/[^a-z]/g, '');
}

/**
 * English-likeness score in [0,1]: the fraction of a label's adjacent letter
 * pairs that are common English bigrams. Short labels (<4 letters) return 1 —
 * too short to judge, treat as fine (e.g. "rbc", "bmo", "td").
 */
export function englishScore(label) {
  const s = lettersOnly(label);
  if (s.length < 4) return 1;
  let common = 0;
  const pairs = s.length - 1;
  for (let i = 0; i < pairs; i++) {
    if (COMMON_BIGRAMS.has(s.slice(i, i + 2))) common++;
  }
  return common / pairs;
}

/** Longest run of consonants in a label (vowels = a e i o u y). */
function maxConsonantRun(label) {
  const s = lettersOnly(label);
  let run = 0, max = 0;
  for (const ch of s) {
    if ('aeiouy'.includes(ch)) { run = 0; }
    else { run++; if (run > max) max = run; }
  }
  return max;
}

/** Vowel fraction of a label (a e i o u; y excluded — it's often a pseudo-vowel). */
function vowelRatio(label) {
  const s = lettersOnly(label);
  if (!s.length) return 0;
  return (s.match(/[aeiou]/g) || []).length / s.length;
}

// Two-rare-letter bigrams that essentially NEVER occur in real English words or
// brand names. Hitting one is a strong "machine-generated" signal on its own.
// Deliberately excludes compound-prone pairs (cv, cg, kp, pk, vg, gv, hx, xh,
// pv, vp, mj) that show up across syllable/word boundaries in real brands like
// cvshealth, mcgrawhill, workplace.
const STRONG_PAIRS = new Set([
  'fq', 'qw', 'qx', 'qz', 'jx', 'xj', 'zx', 'xz', 'jq', 'qj', 'zq', 'jz', 'zj',
  'wj', 'jw', 'vh', 'hv', 'hj', 'jh', 'kx', 'xk', 'bq', 'qb', 'fz', 'zf',
  'gx', 'xg', 'vf', 'fv', 'wx', 'xw', 'vk', 'kv', 'gq', 'qg', 'hq', 'qh',
]);

/** True if the label contains a never-in-English consonant pair. */
function hasStrongPair(s) {
  for (let i = 0; i < s.length - 1; i++) {
    if (STRONG_PAIRS.has(s.slice(i, i + 2))) return true;
  }
  return false;
}

/** True if a `q` is not followed by `u` (a weak machine-generated hint). */
function hasQNotU(s) {
  for (let i = 0; i < s.length - 1; i++) {
    if (s[i] === 'q' && s[i + 1] !== 'u') return true;
  }
  return false;
}

/**
 * Shared high-precision "looks algorithmically random" test.
 *
 * Real brand strings can be long or consonant-heavy (lightspeed, cvshealth,
 * qatarairways) without being random, so a single weak signal is not enough.
 * A label is random only if it is long AND either trips one *strong* signal or
 * at least TWO independent *weak* signals.
 *
 *   strong (alone):  a never-in-English consonant pair, OR a 6+ consonant run,
 *                    OR no vowels at all.
 *   weak (need 2):   5-consonant run, vowel ratio < 0.25, English-bigram score
 *                    < 0.30, or a `q` not followed by `u`.
 *
 * @param {string} raw     the label or mailbox name
 * @param {number} minLen  minimum letter count to judge (short strings are safe)
 */
function looksRandom(raw, minLen) {
  const s = lettersOnly(raw);
  if (s.length < minLen) return false;
  const run = maxConsonantRun(s);
  const vr = vowelRatio(s);
  if (hasStrongPair(s) || run >= 6 || vr === 0) return true;
  let weak = 0;
  if (run >= 5) weak++;
  if (vr < 0.25) weak++;
  if (englishScore(s) < 0.30) weak++;
  if (hasQNotU(s)) weak++;
  return weak >= 2;
}

/**
 * Does a single label look algorithmically random?
 * High-precision multi-signal test (see looksRandom). Requires length >= 8 so
 * real short brands ("rbc", "outlook") are never flagged.
 */
export function looksRandomLabel(label) {
  return looksRandom(label, 8);
}

/** Splits a host into its labels, lowercased (drops empty). */
export function hostLabels(host) {
  return String(host || '').toLowerCase().split('.').filter(Boolean);
}

/**
 * Number of labels in a host (subdomain depth proxy). Legit mail domains are
 * usually 2–3 labels (sub.example.com); deep chains like
 * a.b.c.example.biz.id are a throwaway-domain tell.
 */
export function labelCount(host) {
  return hostLabels(host).length;
}

/**
 * Does any meaningful label of the host look random? We skip the rightmost two
 * labels (registrable domain + TLD are checked but commonly include the brand),
 * actually we DO check the registrable label too — scammers randomize it — but
 * we always skip obvious public-suffix-ish 2-letter TLD labels.
 */
export function hasGibberishLabel(host) {
  const labels = hostLabels(host);
  if (labels.length === 0) return false;
  // Examine every label except a trailing pure-TLD label (len <= 3, e.g. com/ca/me/id).
  const examine = labels.filter((l, i) => !(i === labels.length - 1 && l.length <= 3));
  return examine.some(looksRandomLabel);
}

/** Does the mailbox name (before @) look random/auto-generated? */
export function isRandomLocalPart(localPart) {
  const s = lettersOnly(localPart);
  if (s.length < 8) return false;             // short names like "info","sales" ok
  // Common automated mailboxes are fine even if long.
  const ok = ['noreply', 'donotreply', 'notifications', 'notification', 'support',
    'customerservice', 'billing', 'newsletter', 'marketing', 'accounts', 'service'];
  if (ok.some((w) => s.includes(w))) return false;
  // Same high-precision multi-signal test used for domain labels.
  return looksRandom(s, 8);
}

/** Compound/abused TLD suffixes that are cheap and heavily abused by scammers. */
const ABUSED_TLD_SUFFIXES = [
  '.eu.com', '.biz.id', '.web.id', '.or.id', '.co.id', '.my.id', '.ru.com',
  '.cn.com', '.sa.com', '.us.com', '.uk.com', '.gb.com', '.za.com', '.br.com',
];

/** True if the host ends with a known cheap/abused compound suffix. */
export function hasAbusedTld(host) {
  const h = String(host || '').toLowerCase();
  return ABUSED_TLD_SUFFIXES.some((sfx) => h.endsWith(sfx));
}

/** True if any non-TLD label mixes letters and digits (e.g. "again999"). */
export function hasDigitMixedLabel(host) {
  const labels = hostLabels(host);
  return labels.some((l, i) =>
    !(i === labels.length - 1) && /[a-z]/.test(l) && /\d/.test(l) && l.length >= 5
  );
}
