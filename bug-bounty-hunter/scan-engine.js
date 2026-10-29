/* =============================================================================
   Bug Bounty Hunter — shared detection engine
   Pure logic: patterns, validation, taint analysis, path triage. No DOM, no
   chrome.* — loaded by the content script AND by the popup, and unit-tested
   directly under Node (tests/engine.test.js).
   ============================================================================= */

const ScanEngine = (function () {
  'use strict';

  const MAX_FINDINGS = 300;   // per category, per scan
  const MAX_SINKS = 200;
  const TAINT_WINDOW = 120;   // chars around a sink that count as "near"

  // ==========================================================================
  // Validation helpers — cut the false positives that make scanners noisy
  // ==========================================================================

  function shannonEntropy(s) {
    if (!s) return 0;
    const freq = Object.create(null);
    for (let i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    let h = 0;
    for (const c in freq) {
      const p = freq[c] / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function luhn(raw) {
    const digits = (raw || '').replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (dbl) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  // Placeholder values that look like secrets but are not: docs samples,
  // template vars, obviously fake keys.
  const PLACEHOLDER_RE = /^(x{4,}|\*+|-+|0+|1234567890+|your[-_].*|<.*>|\$\{.*\}|%s.*|process\.env\..*|os\.environ.*|changeme|example|examples?|placeholder|redacted|dummy|sample|testtest.*|fake.*|insert.*here.*|api[_-]?key.*here.*|define.*key.*|some[_-]?key.*|abc123.*|foo.*|bar.*|null|undefined|none|n\/a)$/i;

  function isPlaceholder(v) {
    if (!v) return true;
    const s = String(v).trim();
    if (s.length < 6) return true;
    if (PLACEHOLDER_RE.test(s)) return true;
    // Single repeated character, or missing-template syntax
    if (/^(.)\1*$/.test(s)) return true;
    if (s.includes('${') || s.includes('{{') || s.includes('...')) return true;
    return false;
  }

  // Entropy gate for "generic" secrets (labels + 32 char blobs) where a bad
  // value is indistinguishable from a hash of something harmless.
  function plausibleSecret(v) {
    if (isPlaceholder(v)) return false;
    if (shannonEntropy(v) < 3.2) return false;
    // Must actually mix classes — all-lowercase runs are usually words/hashes
    if (!/[a-z]/.test(v) || !/[A-Z0-9]/.test(v)) return false;
    return true;
  }

  // ==========================================================================
  // Credential patterns — ordered: specific beats generic (dedup keeps first)
  // ==========================================================================

  const PATTERNS = [
    // --- critical: live keys that must be rotated on sight ---
    { type: 'Private Key', severity: 'critical',
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{40,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
      cap: 120 },
    { type: 'AWS Access Key ID', severity: 'critical', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: 'AWS Secret Access Key', severity: 'critical', group: 1,
      re: /(?:aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key|secretAccessKey)["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi },
    { type: 'OpenAI API Key', severity: 'critical', re: /\bsk-(?:proj-|pos-|admin-)?[A-Za-z0-9_-]{20,}\b/g },
    { type: 'Anthropic API Key', severity: 'critical', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
    { type: 'Stripe Live Key', severity: 'critical', re: /\b[rs]k_live_[A-Za-z0-9]{24,}\b/g },
    { type: 'SendGrid API Key', severity: 'critical', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },

    // --- high: provider tokens and live credentials ---
    { type: 'GitHub Token', severity: 'high', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g },
    { type: 'GitLab Token', severity: 'high', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
    { type: 'Slack Token', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { type: 'Slack Webhook', severity: 'high', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
    { type: 'Stripe Test Key', severity: 'medium', re: /\b[rs]k_test_[A-Za-z0-9]{24,}\b/g },
    { type: 'Google API Key', severity: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { type: 'Hugging Face Token', severity: 'high', re: /\bhf_[A-Za-z0-9]{30,}\b/g },
    { type: 'npm Token', severity: 'high', re: /\bnpm_[A-Za-z0-9]{30,}\b/g },
    { type: 'PyPI Token', severity: 'high', re: /\bpypi-[A-Za-z0-9_-]{30,}\b/g },
    { type: 'Twilio API Key', severity: 'high', re: /\bSK[0-9a-fA-F]{32}\b/g },
    { type: 'Telegram Bot Token', severity: 'high', re: /\b\d{8,10}:[A-Za-z0-9_-]{35,}\b/g },
    { type: 'Sentry DSN', severity: 'medium', re: /https:\/\/[0-9a-f]{32}@[a-z0-9.-]*ingest\.sentry\.io\/\d+/g },
    { type: 'Firebase URL', severity: 'low', re: /https:\/\/[a-z0-9-]+\.firebaseio\.com\/?[^\s"'`]*|https:\/\/firebasestorage\.googleapis\.com\/[^\s"'`]+/g },
    { type: 'Connection String', severity: 'high',
      re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|mssql):\/\/[^\s/'"]+:[^\s/'"]+@[^\s/'"]+/g,
      check: 'urlCreds' },
    { type: 'URL Basic Auth', severity: 'high',
      re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@[^\s/]+/gi, check: 'urlCreds' },
    { type: 'JWT', severity: 'medium', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g },
    { type: 'Bearer Token', severity: 'medium', re: /\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi },
    { type: 'Plaintext Password', severity: 'high',
      re: /(?:password|passwd|pass|pwd|secret)["'\s:=]+["']([^"'\s]{6,60})["']/gi, group: 1, check: 'notVarName' },
    { type: 'Credit Card', severity: 'medium', re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, check: 'luhn' },
    { type: 'Email', severity: 'info', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },

    // --- generic fallback: labelled 32-40 char secrets, entropy-gated ---
    { type: 'API Key (labelled)', severity: 'medium', check: 'labelledKey' },
    { type: 'Hex Secret', severity: 'info', check: 'hexSecret' },
  ];

  const LABELLED_KEY_RE = /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|secret)\s*["'\s:=]+\s*["']([A-Za-z0-9/+=_-]{20,64})["']/gi;
  const HEX_RE = /\b[0-9a-fA-F]{48,}\b/g;
  const HEX_LABEL_RE = /(key|token|secret|password|auth|salt|signature)/i;
  const EXCLUDE_CTX_RE = /\b(?:[a-z]+hash|sha-?\d+|md5|crc\d*|checksum|integrity|digest|nonce)\b/i;

  function checkPattern(check, text, match, whole) {
    switch (check) {
      case 'luhn':
        return luhn(whole);
      case 'urlCreds':
        // user:pass in a URL — both sides must be real-looking
        return !isPlaceholder((whole.split('://')[1] || '').split('@')[0]);
      case 'notVarName': {
        const v = String(match || '').trim();
        if (/^(process\.env|os\.environ|config|this\.|self\.|window\.)/i.test(v)) return false;
        // password = "password" — the label repeated as the value
        if (/^(password|passwd|pass|pwd|secret|token|auth|apikey|api_key|key)$/i.test(v)) return false;
        return true;
      }
      case 'labelledKey':
        return plausibleSecret(match);
      case 'hexSecret': {
        // Bare long hex is almost always a hash: only report it when a
        // security label sits on the SAME line, and never under a hash/
        // integrity comment. match is the line, whole the value.
        if (!HEX_LABEL_RE.test(match || '')) return false;
        if (EXCLUDE_CTX_RE.test(match || '')) return false;
        return plausibleSecret(whole);
      }
      default:
        return true;
    }
  }

  function lineOf(lineStarts, idx) {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  function lineStartsOf(text) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) starts.push(i + 1);
      if (starts.length > 200000) break;
    }
    return starts;
  }

  /**
   * Scan free text for credentials. Returns deduped, capped findings with
   * severity and (when a line index is supplied) line numbers.
   */
  function scanCredentials(text, context) {
    if (!text) return [];
    const out = [];
    const seen = new Set();
    const lineStarts = lineStartsOf(text);

    const add = (type, severity, value, idx, extra) => {
      if (!value || out.length >= MAX_FINDINGS) return;
      const v = String(value);
      const key = type + '\u0000' + v;
      if (seen.has(key)) return;
      seen.add(key);
      const f = {
        type, severity: severity || 'medium', value: v.length > 600 ? v.slice(0, 600) + '…' : v,
        context: context || '', line: lineOf(lineStarts, idx),
      };
      if (extra) Object.assign(f, extra);
      out.push(f);
    };

    for (const p of PATTERNS) {
      if (p.check === 'labelledKey') {
        let m;
        LABELLED_KEY_RE.lastIndex = 0;
        while ((m = LABELLED_KEY_RE.exec(text)) !== null) {
          if (!plausibleSecret(m[1])) continue;
          add(p.type, p.severity, m[1], m.index + m[0].length - m[1].length);
        }
        continue;
      }
      if (p.check === 'hexSecret') {
        HEX_RE.lastIndex = 0;
        let m;
        while ((m = HEX_RE.exec(text)) !== null) {
          const lineStart = text.lastIndexOf('\n', m.index - 1) + 1;
          const lineEnd = text.indexOf('\n', m.index);
          const line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
          if (!checkPattern('hexSecret', text, line, m[0])) continue;
          add(p.type, 'info', m[0], m.index);
        }
        continue;
      }
      if (p.re) {
        p.re.lastIndex = 0;
        let m;
        while ((m = p.re.exec(text)) !== null) {
          const value = p.group ? m[p.group] : m[0];
          if (!p.check && isPlaceholder(value)) continue;
          if (p.check && !checkPattern(p.check, text, p.group != null ? m[p.group] : m[0], m[0])) continue;
          add(p.type, p.severity, value, m.index + (p.group ? m[0].indexOf(value) : 0),
              p.cap ? { truncated: true } : null);
          if (m[0] === '') p.re.lastIndex++;
        }
      }
    }
    return out;
  }

  // ==========================================================================
  // Sensitive keywords
  // ==========================================================================

  const keywordCache = new Map();
  function keywordRe(kw) {
    let re = keywordCache.get(kw);
    if (!re) {
      re = new RegExp('\\b' + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi');
      keywordCache.set(kw, re);
    }
    return re;
  }

  function scanKeywords(text, keywords) {
    const results = [];
    if (!text) return results;
    const lineStarts = lineStartsOf(text);
    const limit = Math.min(MAX_FINDINGS, results.length + 200);
    for (const kw of keywords || []) {
      if (!kw) continue;
      const re = keywordRe(String(kw).toLowerCase());
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        results.push({ value: m[0], keyword: kw, line: lineOf(lineStarts, m.index) });
        if (results.length >= limit) return results;
        if (m[0] === '') re.lastIndex++;
      }
    }
    return results;
  }

  // ==========================================================================
  // Sinks + proximity taint analysis
  // ==========================================================================

  const SINK_PATTERNS = [
    { pattern: /\beval\s*\(/g, name: 'eval()', severity: 'High' },
    { pattern: /\bsetTimeout\s*\(\s*["'`]/g, name: 'setTimeout with string', severity: 'High' },
    { pattern: /\bsetInterval\s*\(\s*["'`]/g, name: 'setInterval with string', severity: 'High' },
    { pattern: /\bFunction\s*\(/g, name: 'Function constructor', severity: 'High' },
    { pattern: /\bexecScript\s*\(/g, name: 'execScript', severity: 'High' },
    { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment', severity: 'High' },
    { pattern: /\.outerHTML\s*=/g, name: 'outerHTML assignment', severity: 'High' },
    { pattern: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML', severity: 'High' },
    { pattern: /document\.write(ln)?\s*\(/g, name: 'document.write', severity: 'High' },
    { pattern: /\$\s*\([^)]+\)\.(html|append|after|before|replaceWith)\s*\(/g, name: 'jQuery HTML injection', severity: 'Medium' },
    { pattern: /location\.href\s*=/g, name: 'location.href assignment', severity: 'Medium' },
    { pattern: /location\.(assign|replace)\s*\(/g, name: 'location.assign/replace', severity: 'Medium' },
    { pattern: /postMessage\s*\(/g, name: 'postMessage', severity: 'Medium' },
    { pattern: /chrome\.runtime\.sendMessage\s*\(/g, name: 'chrome.runtime.sendMessage', severity: 'Medium' },
    { pattern: /navigator\.sendBeacon\s*\(/g, name: 'sendBeacon', severity: 'Medium' },
    { pattern: /document\.createContextualFragment\s*\(/g, name: 'createContextualFragment', severity: 'Medium' },
  ];

  // Sources used for taint analysis. Positions are computed ONCE per text
  // instead of re-running every source regex against the whole text per sink
  // (the old approach cost ~240 full scans of multi-MB pages).
  const SOURCE_PATTERNS = [
    { pattern: /window\.location/g, name: 'window.location' },
    { pattern: /document\.URL/g, name: 'document.URL' },
    { pattern: /document\.documentURI/g, name: 'document.documentURI' },
    { pattern: /document\.referrer/g, name: 'document.referrer' },
    { pattern: /location\.search/g, name: 'URL params' },
    { pattern: /location\.hash/g, name: 'URL hash' },
    { pattern: /URLSearchParams/g, name: 'URLSearchParams' },
    { pattern: /document\.cookie/g, name: 'document.cookie' },
    { pattern: /event\.data/g, name: 'message event.data' },
    { pattern: /\.value\b/g, name: 'input value' },
    { pattern: /\$\(.*\)\.val\s*\(\s*\)/g, name: 'jQuery .val()' },
    { pattern: /localStorage\.(getItem)?/g, name: 'localStorage' },
    { pattern: /sessionStorage\.(getItem)?/g, name: 'sessionStorage' },
    // NOTE: innerHTML is a sink, not a source — listing it here made every
    // HTML sink taint itself.
  ];

  function sourcePositions(text) {
    const positions = []; // {index, name}
    for (const src of SOURCE_PATTERNS) {
      src.pattern.lastIndex = 0;
      let m;
      let n = 0;
      while ((m = src.pattern.exec(text)) !== null && n < 500) {
        positions.push({ index: m.index, name: src.name });
        n++;
        if (m[0] === '') src.pattern.lastIndex++;
      }
    }
    positions.sort((a, b) => a.index - b.index);
    return positions;
  }

  function taintNear(positions, from, to) {
    const hits = [];
    for (const p of positions) {
      if (p.index + TAINT_WINDOW < from) continue;
      if (p.index > to + TAINT_WINDOW) break;
      if (!hits.includes(p.name)) hits.push(p.name);
    }
    return hits;
  }

  function scanSinks(text, context) {
    const results = [];
    if (!text) return results;
    const lineStarts = lineStartsOf(text);
    const positions = sourcePositions(text);

    for (const sink of SINK_PATTERNS) {
      sink.pattern.lastIndex = 0;
      let m;
      while ((m = sink.pattern.exec(text)) !== null && results.length < MAX_SINKS) {
        const from = m.index;
        const to = m.index + m[0].length;
        const sources = taintNear(positions, from, to);
        results.push({
          type: 'Sink', name: sink.name, severity: sink.severity,
          snippet: text.slice(Math.max(0, from - 60), Math.min(text.length, to + 90)).replace(/\s+/g, ' ').trim(),
          context: context || '', line: lineOf(lineStarts, from),
          potentialSources: sources, hasTaintFlow: sources.length > 0,
        });
        if (m[0] === '') sink.pattern.lastIndex++;
      }
    }
    return results;
  }

  // ==========================================================================
  // Sensitive path triage — turns a link inventory into attack surface
  // ==========================================================================

  const SENSITIVE_PATH_RULES = [
    { re: /(^|\/)\.git(\/|$)/, reason: 'Git directory exposed', severity: 'critical' },
    { re: /(^|\/)\.env(\.|\/|$)/, reason: 'Environment file exposed', severity: 'critical' },
    { re: /(^|\/)id_rsa\b|\.pem$|\.p12$|\.pfx$|\.key$/, reason: 'Key material exposed', severity: 'critical' },
    { re: /\.(sql|bak|old|orig|save|swp|tar\.gz|tgz|zip|rar)($|\?)/, reason: 'Backup file exposed', severity: 'high' },
    { re: /(^|\/)\.(svn|hg|htaccess|htpasswd)(\/|$)/, reason: 'VCS/config exposed', severity: 'high' },
    { re: /(^|\/)\.aws\/|^\/\.DS_Store$/, reason: 'Cloud metadata/config exposed', severity: 'critical' },
    { re: /wp-config\.php|\/wp-admin\/|phpmyadmin|\/pma\//, reason: 'Admin surface exposed', severity: 'high' },
    { re: /\/(admin|administrator|backoffice|dashboard)(\/|$)/i, reason: 'Admin endpoint', severity: 'medium' },
    { re: /\/(actuator|server-status|debug|console|_profiler)(\/|$)/i, reason: 'Debug/ops endpoint', severity: 'medium' },
    { re: /phpinfo\.php|info\.php$|test\.php$/, reason: 'Info disclosure page', severity: 'medium' },
    { re: /\/(graphql|graphiql)(\/|$|\?)/i, reason: 'GraphQL endpoint', severity: 'low' },
    { re: /\.(log|conf\.json|config\.json|settings\.py|web\.config)$/i, reason: 'Config/log exposed', severity: 'medium' },
    { re: /\.map($|\?)/, reason: 'Source map exposed', severity: 'medium' },
  ];

  function classifyPath(path) {
    if (!path) return null;
    for (const rule of SENSITIVE_PATH_RULES) {
      if (rule.re.test(path)) return { path, reason: rule.reason, severity: rule.severity };
    }
    return null;
  }

  function sensitivePaths(paths) {
    const found = [];
    const seen = new Set();
    for (const p of paths || []) {
      const hit = classifyPath(p);
      if (hit && !seen.has(hit.path)) {
        seen.add(hit.path);
        found.push(hit);
      }
    }
    return found;
  }

  // ==========================================================================
  // Hardcoded variables — `const apiKey = "..."` declarations
  // ==========================================================================

  const HARDCODED_RE = /\b(?:var|let|const|self\.[A-Za-z_$][\w$]*|window\.[A-Za-z_$][\w$]*)\s+([A-Za-z_$][\w$]*)\s*=\s*["'`]([^"'`\n]{8,160})["'`]/g;
  const HARDCODED_NAME_RE = /api|key|token|secret|passw|auth|cred|private/i;
  const HARDCODED_VALUE_SKIP = /^(process\.env|os\.environ|\$\{|<|define|this\.|self\.|window\.)/i;

  function scanHardcodedVars(text, context) {
    const out = [];
    if (!text) return out;
    const lineStarts = lineStartsOf(text);
    HARDCODED_RE.lastIndex = 0;
    let m;
    while ((m = HARDCODED_RE.exec(text)) !== null && out.length < MAX_FINDINGS) {
      const name = m[1];
      const value = m[2];
      if (!HARDCODED_NAME_RE.test(name)) continue;
      if (isPlaceholder(value)) continue;
      if (HARDCODED_VALUE_SKIP.test(value)) continue;
      if (/^(.)\1*$/.test(value)) continue;
      out.push({
        type: 'Hardcoded JS Secret', variable: name, value,
        severity: 'high', context: context || '', line: lineOf(lineStarts, m.index),
      });
      if (m[0] === '') HARDCODED_RE.lastIndex++;
    }
    return out;
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  return {
    MAX_FINDINGS, MAX_SINKS,
    shannonEntropy, luhn, isPlaceholder, plausibleSecret,
    scanCredentials, scanKeywords, scanSinks, scanHardcodedVars,
    classifyPath, sensitivePaths,
    lineStartsOf, lineOf,
    SINK_PATTERNS, // popup filters on these names
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ScanEngine;
}
