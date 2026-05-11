/* =============================================================================
   BUG BOUNTY HUNTER - Popup Script
   Handles UI interactions, displays scan results, and manages JS scanner
   ============================================================================= */

// Default keywords for scanning
const DEFAULT_KEYWORDS = [
  'secret', 'api_key', 'password', 'token', 'aws', 'private',
  'admin', 'debug', 'internal', 'jwt', 'oauth', 'bearer',
  'authorization', 'crypt', 'key', 'credential', 'passwd'
];

// Current scan results
let currentResults = null;
let currentSinks = [];

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Setup tab navigation
  setupTabs();
  
  // Setup sink filters
  setupSinkFilters();
  
  // Setup JS scanner input tabs
  setupJSScannerTabs();
  
  // Load custom keywords
  await loadCustomKeywords();
  
  // Perform initial page scan
  await performPageScan();
  
  // Setup event listeners
  setupEventListeners();
});

// =============================================================================
// TAB NAVIGATION
// =============================================================================

function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      // Remove active class from all buttons and content
      tabButtons.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      // Add active class to clicked button and corresponding content
      btn.classList.add('active');
      const tabId = btn.dataset.tab;
      document.getElementById(tabId).classList.add('active');
    });
  });
}

// =============================================================================
// JS SCANNER INPUT TABS
// =============================================================================

function setupJSScannerTabs() {
  const inputTabs = document.querySelectorAll('.input-tab');
  const codeInput = document.getElementById('js-code-input');
  const urlInput = document.getElementById('js-url-input');
  
  inputTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      inputTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      if (tab.dataset.input === 'snippet') {
        codeInput.style.display = 'block';
        urlInput.style.display = 'none';
      } else {
        codeInput.style.display = 'none';
        urlInput.style.display = 'block';
      }
    });
  });
}

// =============================================================================
// SINK FILTERS
// =============================================================================

function setupSinkFilters() {
  const filters = ['filter-high', 'filter-medium', 'filter-taint'];
  
  filters.forEach(filterId => {
    document.getElementById(filterId).addEventListener('change', () => {
      renderSinks(currentSinks);
    });
  });
}

// =============================================================================
// EVENT LISTENERS
// =============================================================================

function setupEventListeners() {
  // Rescan button
  document.getElementById('btn-rescan').addEventListener('click', performPageScan);
  
  // Download report button
  document.getElementById('btn-download').addEventListener('click', downloadReport);
  
  // JS Scan button
  document.getElementById('btn-scan-js').addEventListener('click', scanJavaScript);
  
  // Settings: Save keywords
  document.getElementById('btn-save-keywords').addEventListener('click', saveCustomKeywords);
  
  // Settings: Reset keywords
  document.getElementById('btn-reset-keywords').addEventListener('click', resetKeywords);
  
  // Settings: Clear storage
  document.getElementById('btn-clear-storage').addEventListener('click', clearStorage);
}

// =============================================================================
// PAGE SCANNING
// =============================================================================

async function performPageScan() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    // Send message to content script to perform scan
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'PERFORM_SCAN' });
    
    if (response) {
      currentResults = response;
      currentSinks = response.sinks || [];
      
      // Display results
      displayPageScanResults(response);
      renderSinks(currentSinks);
    }
  } catch (error) {
    console.error('Bug Bounty Hunter: Scan error', error);
    showError('Failed to scan page. Please refresh the page and try again.');
  }
}

function displayPageScanResults(results) {
  // Update summary counts
  document.getElementById('count-keywords').textContent = results.sensitiveKeywords?.length || 0;
  document.getElementById('count-credentials').textContent = results.leakedCredentials?.length || 0;
  document.getElementById('count-paths').textContent = results.urlPaths?.length || 0;
  document.getElementById('count-cookies').textContent = results.sensitiveCookies?.length || 0;
  document.getElementById('count-forms').textContent = results.formEndpoints?.length || 0;
  document.getElementById('count-js-secrets').textContent = results.jsVariables?.length || 0;
  
  // Render each section
  renderKeywords(results.sensitiveKeywords || []);
  renderCredentials(results.leakedCredentials || []);
  renderPaths(results.urlPaths || []);
  renderCookies(results.sensitiveCookies || []);
  renderForms(results.formEndpoints || []);
  renderJSSecrets(results.jsVariables || []);
}

// =============================================================================
// RENDER FUNCTIONS
// =============================================================================

function renderKeywords(keywords) {
  const container = document.getElementById('keywords-results');
  
  if (keywords.length === 0) {
    container.innerHTML = '<p class="no-results">No sensitive keywords found</p>';
    return;
  }
  
  // Group by keyword value
  const grouped = {};
  keywords.forEach(k => {
    const key = k.value.toLowerCase();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(k);
  });
  
  container.innerHTML = Object.entries(grouped).map(([keyword, items]) => `
    <div class="result-item">
      <div class="result-header">
        <span class="result-type badge badge-warning">${escapeHtml(keyword)}</span>
        <span class="result-count">${items.length} occurrences</span>
      </div>
      <div class="result-details">
        ${items.slice(0, 5).map(item => `
          <div class="result-snippet">
            <span class="context">${escapeHtml(item.context)}</span>
            <button class="btn-copy" data-text="${escapeHtml(item.value)}">📋 Copy</button>
          </div>
        `).join('')}
        ${items.length > 5 ? `<p class="more-items">+${items.length - 5} more</p>` : ''}
      </div>
    </div>
  `).join('');
  
  attachCopyButtons(container);
}

function renderCredentials(credentials) {
  const container = document.getElementById('credentials-results');
  
  if (credentials.length === 0) {
    container.innerHTML = '<p class="no-results">No leaked credentials detected</p>';
    return;
  }
  
  // Group by type
  const grouped = {};
  credentials.forEach(c => {
    if (!grouped[c.type]) grouped[c.type] = [];
    grouped[c.type].push(c);
  });
  
  container.innerHTML = Object.entries(grouped).map(([type, items]) => `
    <div class="result-item credential-item">
      <div class="result-header">
        <span class="result-type badge badge-danger">${escapeHtml(type)}</span>
        <span class="result-count">${items.length} found</span>
      </div>
      <div class="result-details">
        ${items.map(item => `
          <div class="result-snippet">
            <code class="credential-value">${maskCredential(item.value)}</code>
            <button class="btn-copy" data-text="${escapeHtml(item.value)}">📋 Copy</button>
            <span class="context">${escapeHtml(item.context)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
  
  attachCopyButtons(container);
}

function renderPaths(paths) {
  const container = document.getElementById('paths-results');
  
  if (paths.length === 0) {
    container.innerHTML = '<p class="no-results">No URL paths extracted</p>';
    return;
  }
  
  container.innerHTML = `
    <div class="result-item">
      <div class="path-list">
        ${paths.map(path => `
          <div class="path-item">
            <span>${escapeHtml(path)}</span>
            <button class="btn-copy" data-text="${escapeHtml(path)}">📋 Copy</button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
  
  attachCopyButtons(container);
}

function renderCookies(cookies) {
  const container = document.getElementById('cookies-results');
  
  if (cookies.length === 0) {
    container.innerHTML = '<p class="no-results">No sensitive cookies found</p>';
    return;
  }
  
  container.innerHTML = cookies.map(cookie => `
    <div class="result-item">
      <div class="result-header">
        <span class="result-type badge badge-info">${escapeHtml(cookie.name)}</span>
      </div>
      <div class="result-details">
        <div class="result-snippet">
          <code>${maskCredential(cookie.value)}</code>
          <button class="btn-copy" data-text="${escapeHtml(cookie.value)}">📋 Copy</button>
          <span class="context">Pattern: ${escapeHtml(cookie.pattern)}</span>
        </div>
      </div>
    </div>
  `).join('');
  
  attachCopyButtons(container);
}

function renderForms(forms) {
  const container = document.getElementById('forms-results');
  
  if (forms.length === 0) {
    container.innerHTML = '<p class="no-results">No forms found</p>';
    return;
  }
  
  container.innerHTML = forms.map(form => `
    <div class="result-item">
      <div class="result-header">
        <span class="result-type badge badge-secondary">${escapeHtml(form.method.toUpperCase())}</span>
        <span class="form-action">${escapeHtml(truncate(form.action, 50))}</span>
      </div>
      <div class="result-details">
        <div class="form-inputs">
          <strong>Inputs:</strong>
          ${form.inputs.length > 0 
            ? form.inputs.map(input => `<span class="input-tag">${escapeHtml(input.name)} (${escapeHtml(input.type)})</span>`).join('')
            : '<span class="no-inputs">No named inputs</span>'}
        </div>
      </div>
    </div>
  `).join('');
}

function renderJSSecrets(secrets) {
  const container = document.getElementById('js-secrets-results');
  
  if (secrets.length === 0) {
    container.innerHTML = '<p class="no-results">No hardcoded JS secrets found</p>';
    return;
  }
  
  container.innerHTML = secrets.map(secret => `
    <div class="result-item credential-item">
      <div class="result-header">
        <span class="result-type badge badge-danger">${escapeHtml(secret.variable)}</span>
      </div>
      <div class="result-details">
        <div class="result-snippet">
          <code class="credential-value">${maskCredential(secret.value)}</code>
          <button class="btn-copy" data-text="${escapeHtml(secret.value)}">📋 Copy</button>
          <span class="context">${escapeHtml(secret.context)}</span>
        </div>
      </div>
    </div>
  `).join('');
  
  attachCopyButtons(container);
}

function renderSinks(sinks) {
  const container = document.getElementById('sinks-results');
  const totalCount = document.getElementById('sink-total-count');
  
  // Apply filters
  const showHigh = document.getElementById('filter-high').checked;
  const showMedium = document.getElementById('filter-medium').checked;
  const showTaintOnly = document.getElementById('filter-taint').checked;
  
  let filtered = sinks.filter(sink => {
    if (sink.severity === 'High' && !showHigh) return false;
    if (sink.severity === 'Medium' && !showMedium) return false;
    if (showTaintOnly && !sink.hasTaintFlow) return false;
    return true;
  });
  
  totalCount.textContent = `${filtered.length} sinks found`;
  
  if (filtered.length === 0) {
    container.innerHTML = '<p class="no-results">No sinks match the current filters</p>';
    return;
  }
  
  // Sort by severity (High first)
  filtered.sort((a, b) => {
    if (a.severity === 'High') return -1;
    if (b.severity === 'High') return 1;
    return 0;
  });
  
  container.innerHTML = filtered.map(sink => `
    <div class="result-item sink-item sink-${sink.severity.toLowerCase()}">
      <div class="result-header">
        <span class="result-type badge badge-${sink.severity.toLowerCase()}">${escapeHtml(sink.name)}</span>
        <span class="severity-badge ${sink.severity.toLowerCase()}">${sink.severity}</span>
        ${sink.hasTaintFlow ? '<span class="taint-badge">⚠️ Taint Flow</span>' : ''}
      </div>
      <div class="result-details">
        <pre class="sink-snippet"><code>${escapeHtml(sink.snippet)}</code></pre>
        <div class="sink-meta">
          <span class="context">${escapeHtml(sink.context)}</span>
          ${sink.potentialSources?.length > 0 ? `
            <span class="sources">Sources: ${sink.potentialSources.join(', ')}</span>
          ` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

// =============================================================================
// JS SCANNER
// =============================================================================

async function scanJavaScript() {
  const activeTab = document.querySelector('.input-tab.active');
  const inputType = activeTab.dataset.input;
  const customKeywordsInput = document.getElementById('custom-keywords');
  
  // Parse custom keywords
  const keywordsStr = customKeywordsInput.value.trim();
  const keywords = keywordsStr 
    ? keywordsStr.split(',').map(k => k.trim()).filter(k => k)
    : DEFAULT_KEYWORDS;
  
  let code = '';
  
  try {
    if (inputType === 'snippet') {
      code = document.getElementById('js-code-input').value;
      if (!code.trim()) {
        showError('Please enter JavaScript code to scan');
        return;
      }
    } else {
      const url = document.getElementById('js-url-input').value.trim();
      if (!url) {
        showError('Please enter a URL to a JavaScript file');
        return;
      }
      
      // Fetch the JS file
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      code = await response.text();
    }
    
    // Send to content script for scanning
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const results = await chrome.tabs.sendMessage(tab.id, {
      type: 'SCAN_JS_CODE',
      code: code,
      keywords: keywords
    });
    
    // Display results
    displayJSScanResults(results);
    
  } catch (error) {
    console.error('Bug Bounty Hunter: JS scan error', error);
    showError(`Failed to scan: ${error.message}`);
  }
}

function displayJSScanResults(results) {
  const container = document.getElementById('js-scan-results');
  container.style.display = 'block';
  
  // Update counts
  document.getElementById('js-keyword-count').textContent = results.keywordMatches?.length || 0;
  document.getElementById('js-credential-count').textContent = results.credentialMatches?.length || 0;
  document.getElementById('js-sink-count').textContent = results.sinkMatches?.length || 0;
  
  // Render keyword matches
  const keywordContainer = document.getElementById('js-keyword-results');
  if (results.keywordMatches && results.keywordMatches.length > 0) {
    keywordContainer.innerHTML = results.keywordMatches.map(match => `
      <div class="js-result-line">
        <span class="line-number">Line ${match.line}</span>
        <code>${escapeHtml(match.content)}</code>
        <span class="keyword-badge">${escapeHtml(match.keyword)}</span>
        <button class="btn-copy" data-text="${escapeHtml(match.content)}">📋 Copy</button>
      </div>
    `).join('');
  } else {
    keywordContainer.innerHTML = '<p class="no-results">No keyword matches</p>';
  }
  
  // Render credential matches
  const credentialContainer = document.getElementById('js-credential-results');
  if (results.credentialMatches && results.credentialMatches.length > 0) {
    credentialContainer.innerHTML = results.credentialMatches.map(cred => `
      <div class="js-result-line">
        <span class="result-type badge badge-danger">${escapeHtml(cred.type)}</span>
        <code class="credential-value">${maskCredential(cred.value)}</code>
        <button class="btn-copy" data-text="${escapeHtml(cred.value)}">📋 Copy</button>
      </div>
    `).join('');
  } else {
    credentialContainer.innerHTML = '<p class="no-results">No credentials found</p>';
  }
  
  // Render sink matches
  const sinkContainer = document.getElementById('js-sink-results');
  if (results.sinkMatches && results.sinkMatches.length > 0) {
    sinkContainer.innerHTML = results.sinkMatches.map(sink => `
      <div class="js-result-line">
        <span class="result-type badge badge-${sink.severity.toLowerCase()}">${escapeHtml(sink.name)}</span>
        <span class="severity-badge ${sink.severity.toLowerCase()}">${sink.severity}</span>
        <code>${escapeHtml(sink.snippet)}</code>
        <button class="btn-copy" data-text="${escapeHtml(sink.snippet)}">📋 Copy</button>
      </div>
    `).join('');
  } else {
    sinkContainer.innerHTML = '<p class="no-results">No sinks detected</p>';
  }
  
  attachCopyButtons(container);
}

// =============================================================================
// SETTINGS FUNCTIONS
// =============================================================================

async function loadCustomKeywords() {
  try {
    const { customKeywords } = await chrome.storage.local.get('customKeywords');
    const keywords = customKeywords || DEFAULT_KEYWORDS;
    
    // Set in JS scanner input
    document.getElementById('custom-keywords').value = keywords.join(', ');
    
    // Set in settings textarea (one per line)
    document.getElementById('settings-keywords').value = keywords.join('\n');
  } catch (error) {
    console.error('Bug Bounty Hunter: Failed to load keywords', error);
  }
}

async function saveCustomKeywords() {
  const textarea = document.getElementById('settings-keywords');
  const keywords = textarea.value
    .split('\n')
    .map(k => k.trim())
    .filter(k => k);
  
  if (keywords.length === 0) {
    showError('Please enter at least one keyword');
    return;
  }
  
  try {
    await chrome.storage.local.set({ customKeywords: keywords });
    
    // Update JS scanner input
    document.getElementById('custom-keywords').value = keywords.join(', ');
    
    showSuccess('Keywords saved successfully!');
  } catch (error) {
    console.error('Bug Bounty Hunter: Failed to save keywords', error);
    showError('Failed to save keywords');
  }
}

async function resetKeywords() {
  try {
    await chrome.storage.local.set({ customKeywords: DEFAULT_KEYWORDS });
    await loadCustomKeywords();
    showSuccess('Keywords reset to defaults');
  } catch (error) {
    console.error('Bug Bounty Hunter: Failed to reset keywords', error);
    showError('Failed to reset keywords');
  }
}

async function clearStorage() {
  try {
    await chrome.storage.local.clear();
    showSuccess('Stored data cleared');
    
    // Reload keywords
    await loadCustomKeywords();
  } catch (error) {
    console.error('Bug Bounty Hunter: Failed to clear storage', error);
    showError('Failed to clear storage');
  }
}

// =============================================================================
// DOWNLOAD REPORT
// =============================================================================

function downloadReport() {
  if (!currentResults) {
    showError('No scan results to download. Please scan a page first.');
    return;
  }
  
  const report = {
    extension: 'Bug Bounty Hunter',
    version: '1.0.0',
    scannedUrl: window.location.href,
    scanTime: currentResults.timestamp,
    summary: {
      sensitiveKeywords: currentResults.sensitiveKeywords?.length || 0,
      leakedCredentials: currentResults.leakedCredentials?.length || 0,
      urlPaths: currentResults.urlPaths?.length || 0,
      sensitiveCookies: currentResults.sensitiveCookies?.length || 0,
      formEndpoints: currentResults.formEndpoints?.length || 0,
      jsVariables: currentResults.jsVariables?.length || 0,
      sinks: currentResults.sinks?.length || 0
    },
    details: {
      sensitiveKeywords: currentResults.sensitiveKeywords || [],
      leakedCredentials: currentResults.leakedCredentials || [],
      urlPaths: currentResults.urlPaths || [],
      sensitiveCookies: currentResults.sensitiveCookies || [],
      formEndpoints: currentResults.formEndpoints || [],
      jsVariables: currentResults.jsVariables || [],
      sinks: currentResults.sinks || []
    }
  };
  
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `bug-bounty-report-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function truncate(str, len) {
  if (str.length <= len) return str;
  return str.substring(0, len) + '...';
}

function maskCredential(value) {
  if (!value || value.length < 8) return '***';
  return value.substring(0, 4) + '•'.repeat(Math.min(value.length - 8, 20)) + value.substring(value.length - 4);
}

function attachCopyButtons(container) {
  container.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const text = btn.dataset.text;
      
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = '✅ Copied!';
        setTimeout(() => {
          btn.textContent = '📋 Copy';
        }, 1500);
      } catch (error) {
        console.error('Failed to copy', error);
      }
    });
  });
}

function showError(message) {
  // Simple error display - could be enhanced with a toast/notification system
  alert(`⚠️ ${message}`);
}

function showSuccess(message) {
  alert(`✅ ${message}`);
}
