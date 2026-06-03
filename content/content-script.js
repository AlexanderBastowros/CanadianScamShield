/**
 * content/content-script.js
 * Canadian Scam Shield — content script
 *
 * Injected at document_idle into every http(s) page.
 *
 * Responsibilities:
 *   1. Notify the service worker that a page has loaded (PAGE_LOAD).
 *   2. Listen for SHOW_BANNER messages from the service worker and inject an
 *      accessible, keyboard-navigable warning banner into the page.
 *
 * MV3 / content-script constraints:
 *   • Classic script — NO ES module `import` syntax.
 *   • All styling lives in overlay.css; this file only creates DOM structure.
 *   • No auto-dismissing; the user must explicitly click "Dismiss".
 */

// ---------------------------------------------------------------------------
// 1. Notify the service worker that this page loaded
// ---------------------------------------------------------------------------

(function notifyPageLoad() {
  try {
    chrome.runtime.sendMessage({ type: 'PAGE_LOAD', url: window.location.href });
  } catch (e) {
    // The extension context may be temporarily unavailable (e.g. on extension
    // reload).  Swallow the error so we never surface an exception to the page.
  }
})();

// ---------------------------------------------------------------------------
// 2. Listen for SHOW_BANNER messages from the service worker
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(function (msg) {
  if (msg.type === 'SHOW_BANNER') {
    injectBanner(msg.level, msg.reasons, msg.officialUrl);
  }
});

// ---------------------------------------------------------------------------
// 3. Banner injection
// ---------------------------------------------------------------------------

/**
 * injectBanner(level, reasons, officialUrl)
 *
 * Creates and inserts a fixed-position warning banner at the top of the page.
 * The banner is idempotent — if one is already present it is not duplicated.
 *
 * Styling is fully delegated to overlay.css; this function only builds the DOM
 * tree and sets ARIA attributes.
 *
 * @param {'low'|'medium'|'high'} level     - Risk level, used as CSS modifier class
 * @param {string[]}              reasons   - Array of human-readable trigger descriptions
 * @param {string|null}           officialUrl - URL of the legitimate institution, if known
 */
function injectBanner(level, reasons, officialUrl) {
  // Idempotency guard — never show more than one banner per page
  if (document.getElementById('css-scam-banner')) return;

  // ── Root element ──────────────────────────────────────────────────────────
  var banner = document.createElement('div');
  banner.id = 'css-scam-banner';
  banner.className = 'css-scam-banner css-scam-banner--' + level;
  banner.setAttribute('role', 'alert');
  banner.setAttribute('aria-live', 'assertive');

  // ── Main warning text ─────────────────────────────────────────────────────
  var message = document.createElement('span');
  message.className = 'css-scam-banner__message';
  message.textContent =
    'Canadian Scam Shield: this site looks suspicious. ' +
    'Be careful before entering personal information.';
  banner.appendChild(message);

  // ── First reason (brief context) ──────────────────────────────────────────
  if (reasons && reasons.length > 0) {
    var firstReason = document.createElement('span');
    firstReason.className = 'css-scam-banner__first-reason';
    firstReason.textContent = reasons[0];
    banner.appendChild(firstReason);
  }

  // ── "Why?" toggle — reveals the full reasons list ─────────────────────────
  if (reasons && reasons.length > 0) {
    // Toggle button
    var whyBtn = document.createElement('button');
    whyBtn.type = 'button';
    whyBtn.className = 'css-scam-banner__btn css-scam-banner__btn--why';
    whyBtn.textContent = 'Why?';
    whyBtn.setAttribute('aria-expanded', 'false');
    whyBtn.setAttribute('aria-controls', 'css-scam-banner-reasons');
    banner.appendChild(whyBtn);

    // Hidden detail panel
    var reasonsPanel = document.createElement('div');
    reasonsPanel.id = 'css-scam-banner-reasons';
    reasonsPanel.className = 'css-scam-banner__reasons';
    reasonsPanel.setAttribute('hidden', '');

    var reasonsList = document.createElement('ul');
    reasonsList.className = 'css-scam-banner__reasons-list';
    for (var i = 0; i < reasons.length; i++) {
      var li = document.createElement('li');
      li.textContent = reasons[i];
      reasonsList.appendChild(li);
    }
    reasonsPanel.appendChild(reasonsList);

    // Optional: link to the official site (built via DOM API — no innerHTML)
    if (officialUrl) {
      var officialLink = document.createElement('p');
      officialLink.className = 'css-scam-banner__official-link';
      officialLink.appendChild(
        document.createTextNode('Looking for the real site? Visit: ')
      );
      var officialAnchor = document.createElement('a');
      officialAnchor.href = officialUrl;
      officialAnchor.rel = 'noopener noreferrer';
      officialAnchor.textContent = officialUrl;
      officialLink.appendChild(officialAnchor);
      reasonsPanel.appendChild(officialLink);
    }

    banner.appendChild(reasonsPanel);

    // Toggle handler
    whyBtn.addEventListener('click', function () {
      var isOpen = reasonsPanel.hasAttribute('hidden') === false;
      if (isOpen) {
        reasonsPanel.setAttribute('hidden', '');
        reasonsPanel.classList.remove('is-open');
        whyBtn.setAttribute('aria-expanded', 'false');
      } else {
        reasonsPanel.removeAttribute('hidden');
        reasonsPanel.classList.add('is-open');
        whyBtn.setAttribute('aria-expanded', 'true');
      }
    });
  }

  // ── Dismiss button ────────────────────────────────────────────────────────
  var dismissBtn = document.createElement('button');
  dismissBtn.type = 'button';
  dismissBtn.className = 'css-scam-banner__btn css-scam-banner__btn--dismiss';
  dismissBtn.textContent = 'Dismiss';
  dismissBtn.addEventListener('click', function () {
    banner.remove();
  });
  banner.appendChild(dismissBtn);

  // ── Insert as first child of body ─────────────────────────────────────────
  if (document.body) {
    document.body.insertBefore(banner, document.body.firstChild);
  }
}
