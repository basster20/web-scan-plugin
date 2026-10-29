/* =============================================================================
   Bug Bounty Hunter — background service worker (MV3)
   Aggregates per-tab findings pushed by content scripts and expires them.

   v1.1: cleanup runs on chrome.alarms — a plain setInterval dies with the
   service worker after ~30s idle, so old results used to linger forever.
   ============================================================================= */

let aggregatedResults = {
  scans: [],
  lastUpdated: null,
};

const RETENTION_MS = 30 * 60 * 1000; // keep per-tab findings for 30 minutes
const MAX_SCANS = 50;

function pruneAndStore() {
  const cutoff = Date.now() - RETENTION_MS;
  aggregatedResults.scans = aggregatedResults.scans.filter(s => s.timestamp > cutoff);
  aggregatedResults.lastUpdated = Date.now();
  try {
    chrome.storage.local.set({ aggregatedResults, lastUpdated: aggregatedResults.lastUpdated });
  } catch (e) { /* storage unavailable */ }
}

function mergeInto(list, additions, keyFn) {
  const seen = new Set(list.map(keyFn));
  for (const item of additions || []) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    list.push(item);
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type !== 'SCAN_RESULTS') return;

  const tabId = sender.tab && sender.tab.id;
  if (!tabId) return;

  let scan = aggregatedResults.scans.find(s => s.tabId === tabId);
  if (!scan) {
    scan = {
      tabId,
      url: (sender.tab && sender.tab.url) || (request.data && request.data.url) || '',
      credentials: [],
      sinks: [],
      corsIssues: [],
      timestamp: Date.now(),
    };
    aggregatedResults.scans.push(scan);
    if (aggregatedResults.scans.length > MAX_SCANS) aggregatedResults.scans.shift();
  }

  const data = request.data || {};
  mergeInto(scan.credentials, data.credentials, c => c.type + '\u0000' + c.value);
  mergeInto(scan.sinks, data.sinks, s => s.name + '\u0000' + s.context);
  mergeInto(scan.corsIssues, data.corsIssues, c => c.url + '\u0000' + c.reason);
  scan.timestamp = Date.now();

  pruneAndStore();
  sendResponse({ success: true });
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('bbh-cleanup', { periodInMinutes: 5 });
  chrome.storage.local.set({
    aggregatedResults: { scans: [], lastUpdated: Date.now() },
    customKeywords: [
      'secret', 'api_key', 'password', 'token', 'aws', 'private',
      'admin', 'debug', 'internal', 'jwt', 'oauth', 'bearer',
      'authorization', 'crypt', 'key', 'credential', 'passwd',
    ],
    extensionVersion: '1.1.0',
  });
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'bbh-cleanup') pruneAndStore();
});
