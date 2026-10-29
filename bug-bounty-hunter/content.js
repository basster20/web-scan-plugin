/* =============================================================================
   Bug Bounty Hunter — content script
   DOM / network plumbing only. Every detection decision lives in
   scan-engine.js (loaded before this file) so the popup and the Node test
   suite exercise the exact same rules.

   Fixes over v1.0: cross-source dedup (a secret in body + HTML + a fetch
   response counts once), bounded result arrays, throttled mutation scanning,
   and taint analysis that looks at code *near* the sink.
   ============================================================================= */

const Engine = typeof ScanEngine !== 'undefined' ? ScanEngine : null;

const MAX_BODY = 1000000;      // scan at most 1MB of visible text
const MAX_HTML = 2000000;      // and 2MB of markup
const MAX_NET = 500000;        // network bodies
const MUTATION_FLUSH_MS = 1200;

const PAGE_KEYWORDS = [
  'admin', 'password', 'secret', 'token', 'api_key', 'apikey', 'internal',
  'debug', 'jwt', 'oauth', 'aws_secret', 'private key', 'passwd',
  'credentials', 'auth', 'bearer', 'encryption', 'crypt',
];

const processedScripts = new Set();
const processedElements = new WeakSet();

function emptyResults() {
  return {
    sensitiveKeywords: [],
    leakedCredentials: [],
    urlPaths: [],
    sensitiveCookies: [],
    formEndpoints: [],
    jsVariables: [],
    sinks: [],
    sensitivePaths: [],
    corsIssues: [],
    timestamp: null,
  };
}

let scanResults = emptyResults();

// Persistent dedup keys for live (network/mutation) findings so a chatty SPA
// can never grow the arrays without bound.
const liveCredKeys = new Set();
const liveSinkKeys = new Set();

function capPush(arr, item, max) {
  if (arr.length < max) arr.push(item);
}

function mergeCredentials(target, findings, seen) {
  if (!Engine || !findings || !seen) return;
  for (const f of findings) {
    const key = f.type + '\u0000' + f.value;
    if (seen.has(key)) continue;
    seen.add(key);
    capPush(target, f, Engine.MAX_FINDINGS);
  }
}

function mergeSinks(target, sinks, context) {
  if (!Engine || !sinks) return;
  for (const s of sinks) {
    const existing = target.find(t => t.name === s.name && t.context === s.context);
    if (existing) {
      existing.count = (existing.count || 1) + 1;
      if (s.hasTaintFlow && !existing.hasTaintFlow) {
        existing.hasTaintFlow = true;
        existing.potentialSources = s.potentialSources;
      }
      continue;
    }
    capPush(target, s, Engine.MAX_SINKS);
  }
}

// =============================================================================
// Page scanning
// =============================================================================

function extractURLPaths() {
  const paths = new Set();

  const addFrom = (attr) => {
    document.querySelectorAll(`[${attr}]`).forEach(el => {
      const raw = el.getAttribute(attr);
      if (!raw || raw.startsWith('#') || raw.startsWith('javascript:')) return;
      try {
        paths.add(new URL(raw, window.location.origin).pathname);
      } catch (e) {
        if (raw.startsWith('/')) paths.add(raw.split('?')[0].split('#')[0]);
      }
    });
  };

  document.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
      try {
        paths.add(new URL(href, window.location.origin).pathname);
      } catch (e) {
        if (href.startsWith('/')) paths.add(href.split('?')[0].split('#')[0]);
      }
    }
  });
  addFrom('action');
  addFrom('data-url');
  addFrom('src');

  paths.add(window.location.pathname);
  return Array.from(paths);
}

function scanCookies() {
  const results = [];
  const sensitive = ['session', 'token', 'auth', 'jwt', 'sid', 'refresh'];
  try {
    for (const cookie of document.cookie.split(';')) {
      const eq = cookie.indexOf('=');
      if (eq < 0) continue;
      const name = cookie.slice(0, eq).trim();
      const value = cookie.slice(eq + 1);
      const lower = name.toLowerCase();
      for (const p of sensitive) {
        if (lower.includes(p)) {
          results.push({
            type: 'Sensitive Cookie', name,
            value: value.length > 50 ? value.slice(0, 50) + '…' : value,
            pattern: p,
          });
          break;
        }
      }
    }
  } catch (e) { /* cookie access denied */ }
  return results;
}

function extractFormEndpoints() {
  const forms = [];
  document.querySelectorAll('form').forEach((form, index) => {
    const inputs = [];
    form.querySelectorAll('input, select, textarea').forEach(input => {
      const name = input.getAttribute('name');
      if (name) inputs.push({ name, type: input.getAttribute('type') || input.tagName.toLowerCase() });
    });
    forms.push({
      formIndex: index,
      method: form.getAttribute('method') || 'GET',
      action: form.getAttribute('action') || window.location.href,
      inputs,
    });
  });
  return forms;
}

function scanInlineScripts(results, seen) {
  document.querySelectorAll('script:not([src])').forEach((script, i) => {
    const scriptId = `inline-script-${i}`;
    if (processedScripts.has(scriptId)) return;
    processedScripts.add(scriptId);

    const code = script.textContent || '';
    if (code.length < 10 || code.length > MAX_HTML) return;

    mergeCredentials(results.leakedCredentials, Engine.scanCredentials(code, scriptId), seen);
    for (const v of Engine.scanHardcodedVars(code, scriptId)) capPush(results.jsVariables, v, Engine.MAX_FINDINGS);
    mergeSinks(results.sinks, Engine.scanSinks(code, scriptId), scriptId);

    // //# sourceMappingURL= in an inline build points at downloadable sources
    const map = code.match(/\/\/#\s*sourceMappingURL=(\S+)/);
    if (map) results.urlPaths.push(map[1]);
  });

  document.querySelectorAll('script[src]').forEach(script => {
    const src = script.getAttribute('src');
    if (!src) return;
    if (processedScripts.has('external-' + src)) return;
    processedScripts.add('external-' + src);
    try {
      results.urlPaths.push(new URL(src, window.location.origin).pathname);
    } catch (e) { /* data: or invalid */ }
  });

  document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover], [onsubmit], [onfocus], [onblur], [onkeyup], [onkeydown]').forEach(el => {
    if (processedElements.has(el)) return;
    processedElements.add(el);
    for (const attr of el.attributes || []) {
      if (!attr.name.startsWith('on') || !attr.value) continue;
      const id = `${el.tagName}-${attr.name}`;
      mergeCredentials(results.leakedCredentials, Engine.scanCredentials(attr.value, id), seen);
      mergeSinks(results.sinks, Engine.scanSinks(attr.value, id), id);
    }
  });
}

function performPageScan() {
  const results = emptyResults();
  const seen = new Set();

  const bodyText = (document.body && document.body.innerText) || '';
  if (bodyText.length > 0 && bodyText.length <= MAX_BODY) {
    for (const k of Engine.scanKeywords(bodyText, PAGE_KEYWORDS)) {
      capPush(results.sensitiveKeywords, { type: 'Sensitive Keyword', value: k.value, context: 'Page body text', line: k.line }, Engine.MAX_FINDINGS);
    }
    mergeCredentials(results.leakedCredentials, Engine.scanCredentials(bodyText, 'Page body text'), seen);
    mergeSinks(results.sinks, Engine.scanSinks(bodyText, 'Page body text'), 'Page body text');
  }

  const html = (document.documentElement && document.documentElement.outerHTML) || '';
  if (html.length > 0 && html.length <= MAX_HTML) {
    mergeCredentials(results.leakedCredentials, Engine.scanCredentials(html, 'HTML source'), seen);
    mergeSinks(results.sinks, Engine.scanSinks(html, 'HTML source'), 'HTML source');
  }

  scanInlineScripts(results, seen);

  results.urlPaths = Array.from(new Set(results.urlPaths.concat(extractURLPaths())));
  results.sensitivePaths = Engine.sensitivePaths(results.urlPaths);
  results.sensitiveCookies = scanCookies();
  results.formEndpoints = extractFormEndpoints();
  results.timestamp = new Date().toISOString();

  scanResults = results;
  try {
    chrome.storage.local.set({
      lastScanResults: results,
      lastScanUrl: window.location.href,
      lastScanTime: Date.now(),
    });
  } catch (e) { /* storage unavailable */ }
  return results;
}

// =============================================================================
// Network interception — deduped, bounded, plus CORS misconfiguration check
// =============================================================================

function recordNetworkFindings(source, text) {
  if (!text || text.length > MAX_NET) return;
  const creds = Engine.scanCredentials(text, source);
  const sinks = Engine.scanSinks(text, source);
  const newCreds = [];
  const newSinks = [];

  for (const f of creds) {
    const key = f.type + '\u0000' + f.value;
    if (liveCredKeys.has(key)) continue;
    liveCredKeys.add(key);
    if (scanResults.leakedCredentials.length < Engine.MAX_FINDINGS) scanResults.leakedCredentials.push(f);
    newCreds.push(f);
  }
  for (const s of sinks) {
    const key = s.name + '\u0000' + source;
    if (liveSinkKeys.has(key)) continue;
    liveSinkKeys.add(key);
    if (scanResults.sinks.length < Engine.MAX_SINKS) scanResults.sinks.push(s);
    newSinks.push(s);
  }
  for (const v of Engine.scanHardcodedVars(text, source)) {
    if (scanResults.jsVariables.length < Engine.MAX_FINDINGS) scanResults.jsVariables.push(v);
  }

  if (newCreds.length || newSinks.length) {
    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_RESULTS',
        data: { credentials: newCreds, sinks: newSinks, url: source },
      }).catch(() => {});
    } catch (e) { /* extension context invalidated */ }
  }
}

function checkCors(url, headers, requestCredentials) {
  try {
    const acao = headers.get('access-control-allow-origin');
    const acac = headers.get('access-control-allow-credentials');
    if (!acao && !acac) return;
    const origin = window.location.origin;
    let severity = null;
    let reason = null;
    if (acac === 'true' && acao !== origin && acao !== 'null') {
      severity = 'high';
      reason = `Allow-Credentials: true with ACAO "${acao}"`;
    } else if (acao === '*' && requestCredentials === 'include') {
      severity = 'medium';
      reason = 'Wildcard ACAO on a credentialed request';
    } else if (acao && acao !== origin && acao !== '*' && acao !== 'null') {
      severity = 'low';
      reason = `Reflects foreign origin "${acao}"`;
    }
    if (!severity) return;
    const issue = { url, acao, acac, severity, reason };
    if (scanResults.corsIssues.length < 20 &&
        !scanResults.corsIssues.some(c => c.url === url && c.reason === reason)) {
      scanResults.corsIssues.push(issue);
      try {
        chrome.runtime.sendMessage({ type: 'SCAN_RESULTS', data: { corsIssues: [issue] } }).catch(() => {});
      } catch (e) { /* context gone */ }
    }
  } catch (e) { /* headers unreadable */ }
}

function patchFetch() {
  if (window.__fetchPatched) return;
  window.__fetchPatched = true;
  const originalFetch = window.fetch;

  window.fetch = function (...args) {
    const reqCreds = (args[1] && args[1].credentials) ||
                     (args[0] && args[0].credentials) || 'same-origin';
    return originalFetch.apply(this, args).then(response => {
      try {
        checkCors(response.url || String(args[0]), response.headers, reqCreds);
        const clone = response.clone();
        clone.text().then(text => {
          const label = `Fetch: ${response.url || args[0]}`;
          recordNetworkFindings(label, text);
        }).catch(() => {});
      } catch (e) { /* opaque responses */ }
      return response;
    });
  };
}

function patchXHR() {
  if (window.__xhrPatched) return;
  window.__xhrPatched = true;
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__requestUrl = url;
    this.__requestMethod = method;
    return originalOpen.apply(this, [method, url, ...rest]);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    this.addEventListener('load', function () {
      try {
        checkCors(this.__requestUrl, this.getResponseHeader.bind(this),
                   this.withCredentials ? 'include' : 'same-origin');
        const text = this.responseText;
        if (text && text.length <= MAX_NET) {
          recordNetworkFindings(`XHR (${this.__requestMethod}): ${this.__requestUrl}`, text);
        }
      } catch (e) { /* handler context */ }
    });
    return originalSend.apply(this, args);
  };
}

// =============================================================================
// Mutation observer — throttled instead of one full regex pass per mutation
// =============================================================================

let pendingTexts = [];
let flushTimer = null;

function setupMutationObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type !== 'childList') continue;
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.TEXT_NODE) {
          const t = node.textContent;
          if (t && t.length > 10 && t.length < 10000) pendingTexts.push(t);
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'SCRIPT' && !node.src && node.textContent) {
            pendingTexts.push(node.textContent);
          }
          for (const attr of node.attributes || []) {
            if (attr.name.startsWith('on') && attr.value) pendingTexts.push(attr.value);
          }
        }
      });
    }
    if (pendingTexts.length && !flushTimer) {
      flushTimer = setTimeout(flushMutations, MUTATION_FLUSH_MS);
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit', 'onfocus', 'onblur', 'onkeyup', 'onkeydown'],
  });
}

function flushMutations() {
  flushTimer = null;
  const chunk = pendingTexts.join('\n');
  pendingTexts = [];
  if (!chunk || chunk.length > MAX_HTML) return;
  recordNetworkFindings('Dynamic content', chunk);
}

// =============================================================================
// Message handling — protocol unchanged for the popup
// =============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'PERFORM_SCAN') {
    sendResponse(performPageScan());
  } else if (request.type === 'GET_RESULTS') {
    sendResponse(scanResults);
  } else if (request.type === 'SCAN_JS_CODE') {
    // Kept for compatibility; the popup now scans locally via ScanEngine.
    const code = request.code || '';
    const keywords = request.keywords || PAGE_KEYWORDS;
    const kw = Engine.scanKeywords(code, keywords)
      .map(m => ({ line: m.line, content: code.split('\n')[m.line - 1] || '', keyword: m.keyword }));
    sendResponse({
      keywordMatches: kw,
      credentialMatches: Engine.scanCredentials(code, 'JS Scanner'),
      sinkMatches: Engine.scanSinks(code, 'JS Scanner'),
    });
  }
  return true;
});

// =============================================================================
// Initialization
// =============================================================================

function init() {
  patchFetch();
  patchXHR();
  setupMutationObserver();
  setTimeout(() => {
    try { performPageScan(); } catch (e) { /* page may be gone */ }
  }, 1000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
