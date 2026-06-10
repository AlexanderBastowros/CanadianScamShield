/**
 * content/mail-scanner.js
 * Canadian Scam Shield — webmail scanner (Gmail / Outlook web).
 *
 * Reads the email the user currently has OPEN, extracts its sender, subject,
 * body text and links, and asks the service worker to evaluate it with the
 * Layer 3 message engine (CHECK_MESSAGE). All analysis happens locally in the
 * extension's service worker — the email content is never sent to any server.
 *
 * It then injects a small, dismissible verdict chip into the message header for
 * anything that looks suspicious (low / medium / high). Safe emails get nothing.
 *
 * Constraints:
 *   • Classic content script — NO ES module imports.
 *   • Webmail apps are SPAs: opening a different email does not reload the page,
 *     so we watch the DOM (debounced) and re-evaluate when the open email changes.
 *   • Must never throw into the host page, and must respect the user's
 *     mailScanEnabled setting.
 */

(function () {
  'use strict';

  if (window.top !== window) return; // top frame only

  const CHIP_ID = 'css-mail-chip';
  const CAP_TEXT = 20000;
  const CAP_ANCHORS = 60;

  // Localized labels, fetched from the service worker once (falls back to EN).
  let L = {
    app_name: 'Canadian Scam Shield',
    popup_why: 'Why?',
    banner_dismiss: 'Dismiss',
    check_verdict_low: 'A few things to watch',
    check_verdict_medium: 'This looks suspicious',
    check_verdict_high: 'This looks like a scam',
    check_official_contact: 'If you want to confirm, contact {name} directly:',
    check_advice_caution:
      'Do not click links, call numbers, or send money or codes from this message. '
      + 'Contact the organization using a number you find yourself.',
    mail_scan_button: 'Scan this email',
    mail_no_email:
      'Couldn’t find an open email. Select the message text, then click "Scan this email" again.',
  };

  let lastSignature = null;
  let debounceTimer = null;

  // -------------------------------------------------------------------------
  // Provider configuration
  // -------------------------------------------------------------------------

  const host = location.host;

  /**
   * Each provider returns the open email or null. Selectors are best-effort and
   * wrapped so a DOM change in the provider never breaks the page.
   */
  const PROVIDERS = {
    gmail() {
      const subjectEl = document.querySelector('h2.hP');
      if (!subjectEl) return null; // no open email
      const subject = (subjectEl.textContent || '').trim();

      // Sender: first address node in the open message header
      const senderEl = document.querySelector('.gD[email], span[email]');
      const senderName = senderEl ? (senderEl.textContent || '').trim() : '';
      const senderEmail = senderEl ? (senderEl.getAttribute('email') || '') : '';
      const sender = senderEmail ? `${senderName} <${senderEmail}>` : senderName;

      // Bodies: all expanded message bodies in the thread
      const bodyEls = document.querySelectorAll('.a3s');
      let text = '';
      const anchors = [];
      bodyEls.forEach((b) => {
        text += '\n' + (b.innerText || b.textContent || '');
        b.querySelectorAll('a[href]').forEach((a) => {
          if (anchors.length < CAP_ANCHORS) anchors.push({ href: a.href, text: (a.textContent || '').trim() });
        });
      });

      return { subject, sender, text, anchors, anchorEl: subjectEl, insertAfter: subjectEl };
    },

    outlook() {
      const main = document.querySelector('div[role="main"]');
      if (!main) return null;
      const heading = main.querySelector('[role="heading"]');
      const subject = heading ? (heading.textContent || '').trim() : '';
      if (!subject) return null;

      // Sender: a span carrying an email address in title/text
      let sender = '';
      const senderEl = main.querySelector('span[title*="@"], span[aria-label*="@"]');
      if (senderEl) sender = senderEl.getAttribute('title') || senderEl.textContent || '';

      const doc = main.querySelector('div[role="document"]') || main;
      const text = doc.innerText || doc.textContent || '';
      const anchors = [];
      doc.querySelectorAll('a[href]').forEach((a) => {
        if (anchors.length < CAP_ANCHORS) anchors.push({ href: a.href, text: (a.textContent || '').trim() });
      });

      return { subject, sender, text, anchors, anchorEl: heading, insertAfter: heading };
    },
  };

  function detectProvider() {
    if (host.includes('mail.google.com')) return PROVIDERS.gmail;
    if (host.includes('outlook.')) return PROVIDERS.outlook;
    return null;
  }

  // -------------------------------------------------------------------------
  // Evaluation
  // -------------------------------------------------------------------------

  /** Builds the rawText payload (subject + body + reconstructed anchors). */
  function buildRawText(email) {
    let raw = '';
    if (email.subject) raw += 'Subject: ' + email.subject + '\n';
    raw += (email.text || '').slice(0, CAP_TEXT);
    // Reconstruct anchors so the engine can extract links AND detect
    // display-text vs href mismatches.
    for (const a of email.anchors) {
      raw += `\n<a href="${a.href}">${a.text}</a>`;
    }
    return raw;
  }

  function evaluateOpenEmail() {
    let email = null;
    try {
      const provider = detectProvider();
      if (!provider) return;
      email = provider();
    } catch {
      return; // provider DOM changed — fail safe
    }
    if (!email || !email.insertAfter) { removeChip(); return; }

    const signature = (email.sender || '') + '|' + (email.subject || '');
    if (signature === lastSignature && document.getElementById(CHIP_ID)) return;
    lastSignature = signature;

    const rawText = buildRawText(email);

    try {
      chrome.runtime.sendMessage(
        { type: 'CHECK_MESSAGE', rawText, sender: email.sender, subject: email.subject },
        (result) => {
          if (chrome.runtime.lastError || !result) return;
          renderChip(result, email.insertAfter);
        }
      );
    } catch {
      // extension context invalidated (e.g. reload) — ignore
    }
  }

  // -------------------------------------------------------------------------
  // Chip rendering
  // -------------------------------------------------------------------------

  function removeChip() {
    const existing = document.getElementById(CHIP_ID);
    if (existing) existing.remove();
  }

  function renderChip(result, anchorEl) {
    removeChip();
    const { verdict, firedRules = [], officialContact = null } = result;
    if (verdict === 'safe') return; // stay quiet on clean mail

    const chip = document.createElement('div');
    chip.id = CHIP_ID;
    chip.className = 'css-mail-chip css-mail-chip--' + verdict;
    chip.setAttribute('role', 'alert');

    // Header row
    const headerRow = document.createElement('div');
    headerRow.className = 'css-mail-chip__header';

    const badge = document.createElement('span');
    badge.className = 'css-mail-chip__badge';
    badge.textContent = L.app_name;
    headerRow.appendChild(badge);

    const verdictText = document.createElement('span');
    verdictText.className = 'css-mail-chip__verdict';
    verdictText.textContent = L['check_verdict_' + verdict] || verdict;
    headerRow.appendChild(verdictText);

    chip.appendChild(headerRow);

    // Advice line
    const advice = document.createElement('p');
    advice.className = 'css-mail-chip__advice';
    advice.textContent = L.check_advice_caution;
    chip.appendChild(advice);

    // Why toggle + reasons
    if (firedRules.length > 0) {
      const whyBtn = document.createElement('button');
      whyBtn.type = 'button';
      whyBtn.className = 'css-mail-chip__btn';
      whyBtn.textContent = L.popup_why;
      whyBtn.setAttribute('aria-expanded', 'false');

      const reasons = document.createElement('ul');
      reasons.className = 'css-mail-chip__reasons';
      reasons.hidden = true;
      firedRules.forEach((r) => {
        const li = document.createElement('li');
        li.textContent = String(r.explanation || r.id);
        reasons.appendChild(li);
      });

      whyBtn.addEventListener('click', () => {
        const open = !reasons.hidden;
        reasons.hidden = open;
        whyBtn.setAttribute('aria-expanded', String(!open));
      });

      chip.appendChild(whyBtn);
      chip.appendChild(reasons);
    }

    // Official contact
    if (officialContact && (officialContact.url || officialContact.phone)) {
      const contact = document.createElement('p');
      contact.className = 'css-mail-chip__contact';
      contact.textContent = L.check_official_contact.replace('{name}', String(officialContact.name || ''));
      if (officialContact.phone) {
        const phone = document.createElement('strong');
        phone.textContent = ' ' + officialContact.phone;
        contact.appendChild(phone);
      }
      chip.appendChild(contact);
    }

    // Dismiss
    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.className = 'css-mail-chip__btn css-mail-chip__dismiss';
    dismiss.textContent = L.banner_dismiss;
    dismiss.addEventListener('click', () => chip.remove());
    chip.appendChild(dismiss);

    // Insert just after the subject/heading element, or float it if we have no
    // anchor (manual-scan fallback path).
    if (anchorEl && anchorEl.parentNode) {
      anchorEl.parentNode.insertBefore(chip, anchorEl.nextSibling);
    } else {
      chip.classList.add('css-mail-chip--floating');
      document.body.appendChild(chip);
    }
  }

  // -------------------------------------------------------------------------
  // Manual fallback — floating "Scan this email" button
  // -------------------------------------------------------------------------

  /**
   * Forces a scan even if auto-detection's signature guard would skip it.
   * If the provider selectors find no open email, falls back to the user's
   * current text selection, then to the page's main text — so the user always
   * has a way to check a message the automatic path missed.
   */
  function forceScan() {
    lastSignature = null;
    let email = null;
    try {
      const provider = detectProvider();
      if (provider) email = provider();
    } catch { email = null; }

    if (email && email.insertAfter) {
      const rawText = buildRawText(email);
      sendForRender(rawText, email.sender, email.subject, email.insertAfter);
      return;
    }

    // Fallback: selection → main text
    let text = '';
    try { text = (window.getSelection && window.getSelection().toString()) || ''; } catch { text = ''; }
    if (!text.trim()) {
      const main = document.querySelector('div[role="main"]') || document.body;
      text = (main && (main.innerText || main.textContent)) || '';
    }
    text = text.slice(0, CAP_TEXT).trim();
    if (!text) { toast(L.mail_no_email); return; }
    sendForRender(text, '', '', null); // floating chip
  }

  function sendForRender(rawText, sender, subject, anchorEl) {
    try {
      chrome.runtime.sendMessage(
        { type: 'CHECK_MESSAGE', rawText, sender: sender, subject: subject },
        (result) => {
          if (chrome.runtime.lastError || !result) return;
          if (result.verdict === 'safe') { toast(L.mail_chip_safe || 'No obvious scam signs'); return; }
          renderChip(result, anchorEl);
        }
      );
    } catch { /* context invalidated */ }
  }

  /** Brief, self-dismissing status message (used by the manual path). */
  function toast(message) {
    const existing = document.getElementById('css-mail-toast');
    if (existing) existing.remove();
    const el = document.createElement('div');
    el.id = 'css-mail-toast';
    el.className = 'css-mail-toast';
    el.setAttribute('role', 'status');
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  /** Injects the persistent "Scan this email" floating action button once. */
  function ensureFab() {
    if (document.getElementById('css-mail-fab')) return;
    const fab = document.createElement('button');
    fab.id = 'css-mail-fab';
    fab.type = 'button';
    fab.className = 'css-mail-fab';
    fab.textContent = '🛡 ' + (L.mail_scan_button || 'Scan this email');
    fab.addEventListener('click', forceScan);
    document.body.appendChild(fab);
  }

  // -------------------------------------------------------------------------
  // Lifecycle: settings gate, label fetch, observation
  // -------------------------------------------------------------------------

  function start() {
    // Fetch localized labels (best-effort)
    try {
      chrome.runtime.sendMessage(
        {
          type: 'GET_I18N',
          keys: [
            'app_name', 'popup_why', 'banner_dismiss',
            'check_verdict_low', 'check_verdict_medium', 'check_verdict_high',
            'check_official_contact', 'check_advice_caution',
            'mail_scan_button', 'mail_no_email', 'mail_chip_safe',
          ],
        },
        (resp) => {
          if (!chrome.runtime.lastError && resp && resp.strings) {
            L = Object.assign(L, resp.strings);
            const fab = document.getElementById('css-mail-fab');
            if (fab) fab.textContent = '🛡 ' + L.mail_scan_button;
          }
        }
      );
    } catch { /* ignore */ }

    ensureFab();

    // Debounced re-evaluation on DOM changes (SPA navigation between emails)
    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(evaluateOpenEmail, 600);
    });
    try {
      observer.observe(document.body, { childList: true, subtree: true });
    } catch { /* body not ready — unlikely at document_idle */ }

    // Initial pass
    setTimeout(evaluateOpenEmail, 1200);
  }

  // Expose internals for Node/jsdom testing (no-op in the browser, where there
  // is no CommonJS `module`).
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PROVIDERS, detectProvider, buildRawText, evaluateOpenEmail, forceScan, renderChip, start };
  }

  // Auto-start only inside the extension (where chrome.storage exists).
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    try {
      chrome.storage.sync.get({ mailScanEnabled: true }, (s) => {
        if (chrome.runtime.lastError) { start(); return; }
        if (s.mailScanEnabled) start();
      });
    } catch {
      start();
    }
  }
})();
