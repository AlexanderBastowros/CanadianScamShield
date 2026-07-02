/**
 * content/content-script.js
 * Canadian Scam Shield — content script
 *
 * Injected at document_idle into every http(s) page.
 *
 * Responsibilities:
 *   1. Notify the service worker that a page has loaded (PAGE_LOAD).
 *   2. Extract page features for Layer 2 content analysis (PAGE_FEATURES).
 *   3. Listen for SHOW_BANNER messages from the service worker and inject an
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
// 2. Layer 2 — extract page features and send to the service worker
// ---------------------------------------------------------------------------

/**
 * extractPageFeatures()
 *
 * Collects lightweight signals from the current page DOM for Layer 2 content
 * analysis.  Runs only in the top-level frame so iframes don't contribute
 * duplicate or misleading data.
 *
 * Returns a features object on success, or null if called from a sub-frame or
 * if an unexpected error occurs (we must never throw into the host page).
 *
 * @returns {{
 *   title: string,
 *   metaDescription: string,
 *   text: string,
 *   isHttps: boolean,
 *   url: string,
 *   fields: Array<{name:string, id:string, placeholder:string, type:string, autocomplete:string, labelText:string}>
 * }|null}
 */
function extractPageFeatures() {
  // Only run in the top-level frame — iframes are not our analysis target
  if (window.top !== window) return null;

  try {
    // ── Collect form fields (up to 80) ─────────────────────────────────────
    var fields = [];
    var fieldEls = document.querySelectorAll('input, select, textarea');
    var maxFields = Math.min(fieldEls.length, 80);

    for (var i = 0; i < maxFields; i++) {
      var el = fieldEls[i];

      // Resolve the associated label text
      var labelText = '';
      if (el.id) {
        // Explicit <label for="..."> association
        var labelEl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (labelEl) labelText = labelEl.textContent;
      }
      if (!labelText) {
        // Implicit label wrapping the element
        var closestLabel = el.closest('label');
        if (closestLabel) labelText = closestLabel.textContent;
      }
      // Trim and collapse internal whitespace; cap at 120 characters
      labelText = labelText.trim().replace(/\s+/g, ' ').slice(0, 120);

      var descriptor = {
        name:         el.name         || '',
        id:           el.id           || '',
        placeholder:  el.placeholder  || '',
        type:         (el.type        || 'text').toLowerCase(),
        autocomplete: (el.autocomplete || '').toLowerCase(),
        labelText:    labelText,
      };

      // Only include fields that carry at least one non-empty descriptor;
      // bare <input type="hidden"> elements with no labels are not useful.
      var hasSignal =
        descriptor.name         !== '' ||
        descriptor.id           !== '' ||
        descriptor.placeholder  !== '' ||
        descriptor.autocomplete !== '' ||
        descriptor.labelText    !== '';

      if (hasSignal) fields.push(descriptor);
    }

    return {
      title:           (document.title || '').slice(0, 300),
      metaDescription: (document.querySelector('meta[name="description"]')?.content || '').slice(0, 500),
      text:            (document.body?.innerText || '').slice(0, 30000),
      isHttps:         location.protocol === 'https:',
      url:             location.href,
      fields:          fields,
    };
  } catch (e) {
    // Something unexpected failed — never propagate errors to the host page
    return null;
  }
}

/**
 * sendFeatures()
 *
 * Calls extractPageFeatures() and, if successful, sends the result to the
 * service worker as a PAGE_FEATURES message.  Wrapped in try/catch to
 * survive extension-context unavailability.
 */
function sendFeatures() {
  // Guard: only the top frame sends features
  if (window.top !== window) return;

  try {
    var f = extractPageFeatures();
    if (f) {
      chrome.runtime.sendMessage({ type: 'PAGE_FEATURES', url: location.href, features: f });
    }
  } catch (e) {
    // Extension context unavailable or message channel closed — safe to ignore
  }
}

// Schedule feature extraction after the page is idle so we never block
// rendering.  requestIdleCallback is preferred; setTimeout(0) is the fallback
// for environments that don't support it (e.g. some older WebViews).
if (window.top === window) {
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(sendFeatures, { timeout: 2000 });
  } else {
    setTimeout(sendFeatures, 0);
  }
}

// ---------------------------------------------------------------------------
// 3. Listen for SHOW_BANNER messages from the service worker
// ---------------------------------------------------------------------------

// English fallbacks, overwritten by GET_I18N so the banner renders in the
// user's language (this classic script cannot import lib/i18n.js directly).
var BANNER_KEYS = ['banner_caution', 'banner_learn_more', 'banner_dismiss', 'report_short', 'banner_official_site'];
var BANNER_L = {
  banner_caution:
    'Canadian Scam Shield: this site looks suspicious. ' +
    'Be careful before entering any personal information.',
  banner_learn_more: 'Why?',
  banner_dismiss: 'Dismiss',
  report_short: 'Report a mistake',
  banner_official_site: 'Looking for the real site? Visit:',
};

chrome.runtime.onMessage.addListener(function (msg) {
  if (msg.type === 'SHOW_BANNER') {
    // Fetch localized strings first; fall back to English on any failure so
    // the warning always shows.
    try {
      chrome.runtime.sendMessage({ type: 'GET_I18N', keys: BANNER_KEYS }, function (res) {
        if (!chrome.runtime.lastError && res && res.strings) {
          for (var k in res.strings) {
            if (res.strings[k] && res.strings[k] !== k) BANNER_L[k] = res.strings[k];
          }
        }
        injectBanner(msg.level, msg.reasons, msg.officialUrl);
      });
    } catch (e) {
      injectBanner(msg.level, msg.reasons, msg.officialUrl);
    }
  }
});

// ---------------------------------------------------------------------------
// 4. Banner injection
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
  message.textContent = BANNER_L.banner_caution;
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
    whyBtn.textContent = BANNER_L.banner_learn_more;
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
        document.createTextNode(BANNER_L.banner_official_site + ' ')
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

  // ── "Report a mistake" button (false positive) ────────────────────────────
  var reportBtn = document.createElement('button');
  reportBtn.type = 'button';
  reportBtn.className = 'css-scam-banner__btn css-scam-banner__btn--report';
  reportBtn.textContent = BANNER_L.report_short;
  reportBtn.addEventListener('click', function () {
    try {
      chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_POSITIVE',
        kind: 'site',
        reportedUrl: window.location.href,
        verdict: level,
        reasons: reasons || [],
      });
    } catch (e) { /* extension context unavailable */ }
  });
  banner.appendChild(reportBtn);

  // ── Dismiss button ────────────────────────────────────────────────────────
  var dismissBtn = document.createElement('button');
  dismissBtn.type = 'button';
  dismissBtn.className = 'css-scam-banner__btn css-scam-banner__btn--dismiss';
  dismissBtn.textContent = BANNER_L.banner_dismiss;
  dismissBtn.addEventListener('click', function () {
    banner.remove();
  });
  banner.appendChild(dismissBtn);

  // ── Insert as first child of body ─────────────────────────────────────────
  if (document.body) {
    document.body.insertBefore(banner, document.body.firstChild);
  }
}
