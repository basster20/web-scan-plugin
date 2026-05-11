/* =============================================================================
   BUG BOUNTY HUNTER - Content Script
   Scans the current page for sensitive data, credentials, sinks, and vulnerabilities
   Runs at document_start to capture all dynamic content
   ============================================================================= */

// Store scan results globally
let scanResults = {
  sensitiveKeywords: [],
  leakedCredentials: [],
  urlPaths: new Set(),
  sensitiveCookies: [],
  formEndpoints: [],
  jsVariables: [],
  sinks: [],
  timestamp: null
};

// Prevent duplicate processing
const processedScripts = new Set();
const processedElements = new WeakSet();

// =============================================================================
// REGEX PATTERNS - Efficient, non-catastrophic patterns
// =============================================================================

// Sensitive keywords (case-insensitive matching done in code)
const SENSITIVE_KEYWORDS = [
  'admin', 'password', 'secret', 'token', 'api_key', 'apikey', 'internal',
  'debug', 'jwt', 'oauth', 'aws_secret', 'private key', 'passwd',
  'credentials', 'auth', 'bearer', 'encryption', 'crypt'
];

// Email pattern - standard RFC 5322 simplified (efficient, no backtracking)
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// Generic API keys - 32-40 alphanumeric characters with common prefixes
const API_KEY_REGEX = /(?:api[_-]?key|apikey|key|token)["'\s:=]+["']?([a-zA-Z0-9_-]{32,40})["']?/gi;

// AWS Access Key ID (starts with AKIA)
const AWS_KEY_REGEX = /AKIA[0-9A-Z]{16}/g;

// AWS Secret Access Key (40 char base64-like after aws_secret/access_key)
const AWS_SECRET_REGEX = /(?:aws[_-]?secret|aws[_-]?access)[_\-]?(?:key)?["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi;

// GitHub Personal Access Token (ghp_, gho_, ghu_, ghs_, ghr_)
const GITHUB_TOKEN_REGEX = /gh[pousr]_[A-Za-z0-9_]{36,}/g;

// Slack Token (xoxb-, xoxp-, xoxa-)
const SLACK_TOKEN_REGEX = /xox[bpaors]-[A-Za-z0-9-]+/g;

// Stripe API Key (sk_live_, pk_live_, sk_test_, pk_test_)
const STRIPE_KEY_REGEX = /[sr]k_(live|test)_[A-Za-z0-9]{24,}/g;

// Google API Key (AIza)
const GOOGLE_API_KEY_REGEX = /AIza[0-9A-Za-z_-]{35}/g;

// Bearer token in headers/auth
const BEARER_TOKEN_REGEX = /bearer\s+[a-zA-Z0-9._-]+/gi;

// JWT Token (eyJ开头，base64url encoded)
const JWT_TOKEN_REGEX = /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g;

// Long hex strings (potential tokens/keys) - 64+ hex chars
const HEX_TOKEN_REGEX = /\b[0-9a-fA-F]{64,}\b/g;

// Password patterns in plaintext
const PASSWORD_PLAINTEXT_REGEX = /(?:password|passwd|pass|pwd)["'\s:=]+["']([^"']{4,})["']/gi;

// Credit Card Numbers (basic pattern, 13-19 digits with optional separators)
const CC_REGEX = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;

// Private Keys (RSA, SSH, generic)
const PRIVATE_KEY_REGEX = /-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+KEY|OPENSSH\s+PRIVATE\s+KEY)-----[\s\S]*?-----END\s+(?:RSA\s+)?(?:PRIVATE\s+KEY|OPENSSH\s+PRIVATE\s+KEY)-----/g;

// Hardcoded JS variables with secrets
const JS_SECRET_VAR_REGEX = /(?:var|let|const)\s+(?:apiKey|api_key|apikey|secret|password|passwd|token|authKey|auth_token|privateKey|private_key)\s*=\s*["']([^"']+)["']/gi;

// =============================================================================
// SINK PATTERNS - Dangerous functions that can lead to XSS or other vulns
// =============================================================================

const SINK_PATTERNS = [
  // High severity - code execution
  { pattern: /\beval\s*\(/g, name: 'eval()', severity: 'High' },
  { pattern: /\bsetTimeout\s*\(\s*["'`]/g, name: 'setTimeout with string', severity: 'High' },
  { pattern: /\bsetInterval\s*\(\s*["'`]/g, name: 'setInterval with string', severity: 'High' },
  { pattern: /\bFunction\s*\(/g, name: 'Function constructor', severity: 'High' },
  { pattern: /\bexecScript\s*\(/g, name: 'execScript', severity: 'High' },
  
  // High severity - DOM manipulation
  { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment', severity: 'High' },
  { pattern: /\.outerHTML\s*=/g, name: 'outerHTML assignment', severity: 'High' },
  { pattern: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML', severity: 'High' },
  { pattern: /document\.write\s*\(/g, name: 'document.write', severity: 'High' },
  { pattern: /document\.writeln\s*\(/g, name: 'document.writeln', severity: 'High' },
  
  // Medium severity - jQuery sinks
  { pattern: /\$\s*\([^)]+\)\.html\s*\(/g, name: 'jQuery .html()', severity: 'Medium' },
  { pattern: /\$\s*\([^)]+\)\.append\s*\(/g, name: 'jQuery .append()', severity: 'Medium' },
  { pattern: /\$\s*\([^)]+\)\.after\s*\(/g, name: 'jQuery .after()', severity: 'Medium' },
  { pattern: /\$\s*\([^)]+\)\.before\s*\(/g, name: 'jQuery .before()', severity: 'Medium' },
  { pattern: /\$\.html\s*\(/g, name: 'jQuery $.html()', severity: 'Medium' },
  
  // Medium severity - navigation
  { pattern: /location\.href\s*=/g, name: 'location.href assignment', severity: 'Medium' },
  { pattern: /location\.assign\s*\(/g, name: 'location.assign', severity: 'Medium' },
  { pattern: /location\.replace\s*\(/g, name: 'location.replace', severity: 'Medium' },
  
  // Medium severity - messaging
  { pattern: /postMessage\s*\(/g, name: 'postMessage', severity: 'Medium' },
  { pattern: /chrome\.runtime\.sendMessage\s*\(/g, name: 'chrome.runtime.sendMessage', severity: 'Medium' }
];

// Potential sources for taint analysis
const SOURCE_PATTERNS = [
  { pattern: /window\.location/g, name: 'window.location' },
  { pattern: /document\.URL/g, name: 'document.URL' },
  { pattern: /document\.referrer/g, name: 'document.referrer' },
  { pattern: /location\.search/g, name: 'URL params' },
  { pattern: /location\.hash/g, name: 'URL hash' },
  { pattern: /document\.cookie/g, name: 'document.cookie' },
  { pattern: /\$\(.*\)\.val\(\)/g, name: 'jQuery .val()' },
  { pattern: /\.value/g, name: 'input value' },
  { pattern: /localStorage\./g, name: 'localStorage' },
  { pattern: /sessionStorage\./g, name: 'sessionStorage' }
];

// =============================================================================
// MAIN SCANNING FUNCTIONS
// =============================================================================

/**
 * Scan text content for sensitive keywords
 */
function scanForSensitiveKeywords(text, context = '') {
  const results = [];
  const lowerText = text.toLowerCase();
  
  for (const keyword of SENSITIVE_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
    let match;
    while ((match = regex.exec(lowerText)) !== null) {
      // Get original case from text
      const originalMatch = text.substring(match.index, match.index + keyword.length);
      results.push({
        type: 'Sensitive Keyword',
        value: originalMatch,
        context: context || 'Page content',
        position: match.index
      });
    }
  }
  
  return results;
}

/**
 * Scan for leaked credentials using regex patterns
 */
function scanForCredentials(text, context = '') {
  const results = [];
  
  // Helper to add finding without duplicates
  const addFinding = (type, value, pattern) => {
    // Avoid adding very long values or duplicates
    if (value && value.length < 500 && !results.find(r => r.value === value)) {
      results.push({ type, value, context, pattern });
    }
  };
  
  // Emails
  let matches;
  while ((matches = EMAIL_REGEX.exec(text)) !== null) {
    addFinding('Email', matches[0], 'EMAIL_REGEX');
  }
  
  // AWS Keys
  while ((matches = AWS_KEY_REGEX.exec(text)) !== null) {
    addFinding('AWS Access Key', matches[0], 'AWS_KEY_REGEX');
  }
  
  // AWS Secrets
  while ((matches = AWS_SECRET_REGEX.exec(text)) !== null) {
    addFinding('AWS Secret Key', matches[1] || matches[0], 'AWS_SECRET_REGEX');
  }
  
  // GitHub Tokens
  while ((matches = GITHUB_TOKEN_REGEX.exec(text)) !== null) {
    addFinding('GitHub Token', matches[0], 'GITHUB_TOKEN_REGEX');
  }
  
  // Slack Tokens
  while ((matches = SLACK_TOKEN_REGEX.exec(text)) !== null) {
    addFinding('Slack Token', matches[0], 'SLACK_TOKEN_REGEX');
  }
  
  // Stripe Keys
  while ((matches = STRIPE_KEY_REGEX.exec(text)) !== null) {
    addFinding('Stripe API Key', matches[0], 'STRIPE_KEY_REGEX');
  }
  
  // Google API Keys
  while ((matches = GOOGLE_API_KEY_REGEX.exec(text)) !== null) {
    addFinding('Google API Key', matches[0], 'GOOGLE_API_KEY_REGEX');
  }
  
  // Bearer Tokens
  while ((matches = BEARER_TOKEN_REGEX.exec(text)) !== null) {
    addFinding('Bearer Token', matches[0], 'BEARER_TOKEN_REGEX');
  }
  
  // JWT Tokens
  while ((matches = JWT_TOKEN_REGEX.exec(text)) !== null) {
    addFinding('JWT Token', matches[0], 'JWT_TOKEN_REGEX');
  }
  
  // Hex Tokens
  while ((matches = HEX_TOKEN_REGEX.exec(text)) !== null) {
    addFinding('Hex Token/Key', matches[0], 'HEX_TOKEN_REGEX');
  }
  
  // Passwords in plaintext
  while ((matches = PASSWORD_PLAINTEXT_REGEX.exec(text)) !== null) {
    addFinding('Plaintext Password', matches[1] || matches[0], 'PASSWORD_PLAINTEXT_REGEX');
  }
  
  // Credit Cards
  while ((matches = CC_REGEX.exec(text)) !== null) {
    addFinding('Credit Card Number', matches[0], 'CC_REGEX');
  }
  
  // Private Keys
  while ((matches = PRIVATE_KEY_REGEX.exec(text)) !== null) {
    addFinding('Private Key', matches[0].substring(0, 100) + '...', 'PRIVATE_KEY_REGEX');
  }
  
  // Generic API Keys
  while ((matches = API_KEY_REGEX.exec(text)) !== null) {
    addFinding('API Key', matches[1] || matches[0], 'API_KEY_REGEX');
  }
  
  return results;
}

/**
 * Scan for hardcoded JS variables containing secrets
 */
function scanForJSSecrets(text, context = '') {
  const results = [];
  let matches;
  
  while ((matches = JS_SECRET_VAR_REGEX.exec(text)) !== null) {
    results.push({
      type: 'Hardcoded JS Secret',
      variable: matches[0].split('=')[0].trim(),
      value: matches[1],
      context: context
    });
  }
  
  return results;
}

/**
 * Scan for dangerous sinks in code
 */
function scanForSinks(text, context = '', lineNumber = null) {
  const results = [];
  
  for (const sink of SINK_PATTERNS) {
    // Reset regex lastIndex
    sink.pattern.lastIndex = 0;
    let matches;
    while ((matches = sink.pattern.exec(text)) !== null) {
      // Check for potential sources (taint analysis)
      const sources = [];
      for (const source of SOURCE_PATTERNS) {
        source.pattern.lastIndex = 0;
        if (source.pattern.test(text)) {
          sources.push(source.name);
        }
      }
      
      results.push({
        type: 'Sink',
        name: sink.name,
        severity: sink.severity,
        snippet: text.substring(Math.max(0, matches.index - 50), matches.index + 100).trim(),
        context: context,
        lineNumber: lineNumber,
        potentialSources: sources,
        hasTaintFlow: sources.length > 0
      });
    }
  }
  
  return results;
}

/**
 * Extract URL paths from various sources
 */
function extractURLPaths() {
  const paths = new Set();
  
  // From anchor tags
  document.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
      try {
        const url = new URL(href, window.location.origin);
        paths.add(url.pathname);
      } catch (e) {
        // Relative or invalid URL
        if (href.startsWith('/')) {
          paths.add(href.split('?')[0].split('#')[0]);
        }
      }
    }
  });
  
  // From form actions
  document.querySelectorAll('form[action]').forEach(form => {
    const action = form.getAttribute('action');
    if (action) {
      try {
        const url = new URL(action, window.location.origin);
        paths.add(url.pathname);
      } catch (e) {
        if (action.startsWith('/')) {
          paths.add(action.split('?')[0].split('#')[0]);
        }
      }
    }
  });
  
  // From data-url attributes
  document.querySelectorAll('[data-url]').forEach(el => {
    const url = el.getAttribute('data-url');
    if (url) {
      try {
        const parsed = new URL(url, window.location.origin);
        paths.add(parsed.pathname);
      } catch (e) {
        paths.add(url.split('?')[0].split('#')[0]);
      }
    }
  });
  
  // Current location
  paths.add(window.location.pathname);
  
  return paths;
}

/**
 * Scan cookies for sensitive information
 */
function scanCookies() {
  const results = [];
  const sensitiveCookiePatterns = ['session', 'token', 'auth', 'jwt', 'cookie', 'sid'];
  
  try {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      const lowerName = name.toLowerCase();
      
      for (const pattern of sensitiveCookiePatterns) {
        if (lowerName.includes(pattern)) {
          results.push({
            type: 'Sensitive Cookie',
            name: name,
            value: value ? value.substring(0, 50) + (value.length > 50 ? '...' : '') : '[empty]',
            pattern: pattern
          });
          break;
        }
      }
    }
  } catch (e) {
    // Cookies may not be accessible
  }
  
  return results;
}

/**
 * Extract form endpoint information
 */
function extractFormEndpoints() {
  const forms = [];
  
  document.querySelectorAll('form').forEach((form, index) => {
    const inputs = [];
    form.querySelectorAll('input, select, textarea').forEach(input => {
      const name = input.getAttribute('name');
      const type = input.getAttribute('type') || input.tagName.toLowerCase();
      if (name) {
        inputs.push({ name, type });
      }
    });
    
    forms.push({
      formIndex: index,
      method: form.getAttribute('method') || 'GET',
      action: form.getAttribute('action') || window.location.href,
      inputs: inputs
    });
  });
  
  return forms;
}

/**
 * Scan inline scripts and event handlers
 */
function scanInlineScripts() {
  const results = {
    credentials: [],
    secrets: [],
    sinks: []
  };
  
  // Inline script tags
  document.querySelectorAll('script:not([src])').forEach(script => {
    const scriptId = `inline-script-${processedScripts.size}`;
    if (processedScripts.has(scriptId)) return;
    processedScripts.add(scriptId);
    
    const code = script.textContent || '';
    if (code.length < 10) return;
    
    results.credentials.push(...scanForCredentials(code, scriptId));
    results.secrets.push(...scanForJSSecrets(code, scriptId));
    results.sinks.push(...scanForSinks(code, scriptId));
  });
  
  // External scripts (scan what we can access)
  document.querySelectorAll('script[src]').forEach(script => {
    const src = script.getAttribute('src');
    const scriptId = `external-${src}`;
    if (processedScripts.has(scriptId)) return;
    processedScripts.add(scriptId);
    
    // We can't read external scripts due to CORS, but we can note their presence
    if (src && !src.startsWith('http')) {
      scanResults.urlPaths.add(src.split('?')[0]);
    }
  });
  
  // Event handler attributes
  document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover], [onsubmit], [onfocus], [onblur]').forEach(el => {
    if (processedElements.has(el)) return;
    processedElements.add(el);
    
    const handlers = [];
    for (const attr of el.attributes) {
      if (attr.name.startsWith('on')) {
        handlers.push({ name: attr.name, code: attr.value });
      }
    }
    
    for (const handler of handlers) {
      const handlerId = `handler-${el.tagName}-${handler.name}`;
      results.sinks.push(...scanForSinks(handler.code, handlerId));
      results.credentials.push(...scanForCredentials(handler.code, handlerId));
    }
  });
  
  return results;
}

/**
 * Main page scanning function
 */
function performPageScan() {
  const results = {
    sensitiveKeywords: [],
    leakedCredentials: [],
    urlPaths: [],
    sensitiveCookies: [],
    formEndpoints: [],
    jsVariables: [],
    sinks: []
  };
  
  // Scan visible text content
  const bodyText = document.body?.innerText || '';
  if (bodyText.length > 0 && bodyText.length < 1000000) { // Limit to 1MB
    results.sensitiveKeywords.push(...scanForSensitiveKeywords(bodyText, 'Page body text'));
    results.leakedCredentials.push(...scanForCredentials(bodyText, 'Page body text'));
    results.sinks.push(...scanForSinks(bodyText, 'Page body text'));
  }
  
  // Scan HTML source (for hidden data)
  const htmlContent = document.documentElement?.outerHTML || '';
  if (htmlContent.length > 0 && htmlContent.length < 2000000) { // Limit to 2MB
    results.leakedCredentials.push(...scanForCredentials(htmlContent, 'HTML source'));
    results.sinks.push(...scanForSinks(htmlContent, 'HTML source'));
  }
  
  // Scan inline scripts
  const inlineResults = scanInlineScripts();
  results.leakedCredentials.push(...inlineResults.credentials);
  results.jsVariables.push(...inlineResults.secrets);
  results.sinks.push(...inlineResults.sinks);
  
  // Extract URL paths
  results.urlPaths = Array.from(extractURLPaths());
  
  // Scan cookies
  results.sensitiveCookies = scanCookies();
  
  // Extract form endpoints
  results.formEndpoints = extractFormEndpoints();
  
  // Add timestamp
  results.timestamp = new Date().toISOString();
  
  return results;
}

// =============================================================================
// FETCH AND XHR PATCHING - Capture network responses
// =============================================================================

/**
 * Patch window.fetch to scan responses
 */
function patchFetch() {
  if (window.__fetchPatched) return;
  window.__fetchPatched = true;
  
  const originalFetch = window.fetch;
  
  window.fetch = function(...args) {
    return originalFetch.apply(this, args).then(response => {
      // Clone response to read body without consuming it
      const clone = response.clone();
      
      clone.text().then(text => {
        if (text && text.length < 500000) { // Limit to 500KB
          const url = args[0]?.url || args[0]?.toString() || 'unknown';
          const credentials = scanForCredentials(text, `Fetch: ${url}`);
          const sinks = scanForSinks(text, `Fetch: ${url}`);
          
          if (credentials.length > 0 || sinks.length > 0) {
            // Store in global results
            scanResults.leakedCredentials.push(...credentials);
            scanResults.sinks.push(...sinks);
            
            // Notify background script
            chrome.runtime.sendMessage({
              type: 'SCAN_RESULTS',
              data: { credentials, sinks, url }
            }).catch(() => {}); // Ignore errors if extension context invalidated
          }
        }
      }).catch(() => {}); // Ignore read errors
      
      return response;
    });
  };
}

/**
 * Patch XMLHttpRequest to scan responses
 */
function patchXHR() {
  if (window.__xhrPatched) return;
  window.__xhrPatched = true;
  
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__requestUrl = url;
    this.__requestMethod = method;
    return originalOpen.apply(this, [method, url, ...rest]);
  };
  
  XMLHttpRequest.prototype.send = function(...args) {
    this.addEventListener('load', function() {
      const text = this.responseText;
      if (text && text.length < 500000) {
        const url = this.__requestUrl || 'unknown';
        const credentials = scanForCredentials(text, `XHR (${this.__requestMethod}): ${url}`);
        const sinks = scanForSinks(text, `XHR (${this.__requestMethod}): ${url}`);
        
        if (credentials.length > 0 || sinks.length > 0) {
          scanResults.leakedCredentials.push(...credentials);
          scanResults.sinks.push(...sinks);
          
          chrome.runtime.sendMessage({
            type: 'SCAN_RESULTS',
            data: { credentials, sinks, url }
          }).catch(() => {});
        }
      }
    });
    
    return originalSend.apply(this, args);
  };
}

// =============================================================================
// MUTATION OBSERVER - Scan dynamically added content
// =============================================================================

function setupMutationObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.TEXT_NODE) {
            const text = node.textContent;
            if (text && text.length > 10 && text.length < 10000) {
              const credentials = scanForCredentials(text, 'Dynamic content');
              const sinks = scanForSinks(text, 'Dynamic content');
              
              if (credentials.length > 0 || sinks.length > 0) {
                scanResults.leakedCredentials.push(...credentials);
                scanResults.sinks.push(...sinks);
              }
            }
          } else if (node.nodeType === Node.ELEMENT_NODE) {
            // Check for new scripts or event handlers
            if (node.tagName === 'SCRIPT' && !node.src) {
              const code = node.textContent || '';
              if (code.length > 10) {
                const scriptId = `dynamic-script-${Date.now()}`;
                scanResults.leakedCredentials.push(...scanForCredentials(code, scriptId));
                scanResults.jsVariables.push(...scanForJSSecrets(code, scriptId));
                scanResults.sinks.push(...scanForSinks(code, scriptId));
              }
            }
            
            // Check event handlers on new element
            for (const attr of node.attributes || []) {
              if (attr.name.startsWith('on') && attr.value) {
                const handlerId = `dynamic-handler-${Date.now()}-${attr.name}`;
                scanResults.sinks.push(...scanForSinks(attr.value, handlerId));
              }
            }
          }
        });
      }
    }
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit', 'onfocus', 'onblur', 'onkeyup', 'onkeydown']
  });
}

// =============================================================================
// MESSAGE HANDLING
// =============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'PERFORM_SCAN') {
    // Perform fresh scan
    scanResults = performPageScan();
    sendResponse(scanResults);
  } else if (request.type === 'GET_RESULTS') {
    // Return cached results
    sendResponse(scanResults);
  } else if (request.type === 'SCAN_JS_CODE') {
    // Scan provided JS code (from popup JS scanner)
    const code = request.code;
    const keywords = request.keywords || SENSITIVE_KEYWORDS;
    
    const results = {
      keywordMatches: [],
      credentialMatches: [],
      sinkMatches: []
    };
    
    const lines = code.split('\n');
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lowerLine = line.toLowerCase();
      
      // Check for keywords
      for (const keyword of keywords) {
        if (lowerLine.includes(keyword.toLowerCase())) {
          results.keywordMatches.push({
            line: lineNum,
            content: line.trim(),
            keyword: keyword
          });
        }
      }
    });
    
    // Scan entire code for credentials and sinks
    results.credentialMatches = scanForCredentials(code, 'JS Scanner');
    results.sinkMatches = scanForSinks(code, 'JS Scanner');
    
    sendResponse(results);
  }
  
  return true; // Keep channel open for async response
});

// =============================================================================
// INITIALIZATION
// =============================================================================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

function init() {
  // Patch network methods first (run at document_start ensures this happens early)
  patchFetch();
  patchXHR();
  
  // Setup mutation observer for dynamic content
  setupMutationObserver();
  
  // Perform initial scan after a short delay to allow page to load
  setTimeout(() => {
    scanResults = performPageScan();
    
    // Store results in chrome.storage
    try {
      chrome.storage.local.set({
        lastScanResults: scanResults,
        lastScanUrl: window.location.href,
        lastScanTime: Date.now()
      });
    } catch (e) {
      console.log('Bug Bounty Hunter: Could not store results', e);
    }
  }, 1000);
}
