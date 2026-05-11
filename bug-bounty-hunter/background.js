/* =============================================================================
   BUG BOUNTY HUNTER - Background Service Worker
   Handles messages from content scripts and popup
   ============================================================================= */

// Store aggregated results
let aggregatedResults = {
  scans: [],
  lastUpdated: null
};

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'SCAN_RESULTS') {
    // Content script found something in network responses
    const tabId = sender.tab?.id;
    
    if (tabId) {
      // Get existing results for this tab or create new
      const existingScan = aggregatedResults.scans.find(s => s.tabId === tabId);
      
      if (existingScan) {
        if (request.data.credentials) {
          existingScan.credentials.push(...request.data.credentials);
        }
        if (request.data.sinks) {
          existingScan.sinks.push(...request.data.sinks);
        }
      } else {
        aggregatedResults.scans.push({
          tabId: tabId,
          url: request.data.url || sender.tab?.url,
          credentials: request.data.credentials || [],
          sinks: request.data.sinks || [],
          timestamp: Date.now()
        });
      }
      
      aggregatedResults.lastUpdated = Date.now();
      
      // Update storage
      chrome.storage.local.set({ 
        aggregatedResults,
        lastUpdated: aggregatedResults.lastUpdated 
      });
    }
    
    sendResponse({ success: true });
  }
  
  return true;
});

// Clean up old results periodically (every 5 minutes)
setInterval(() => {
  const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
  aggregatedResults.scans = aggregatedResults.scans.filter(s => s.timestamp > fiveMinutesAgo);
  aggregatedResults.lastUpdated = Date.now();
  
  chrome.storage.local.set({ 
    aggregatedResults,
    lastUpdated: aggregatedResults.lastUpdated 
  });
}, 5 * 60 * 1000);

// Initialize storage on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    aggregatedResults: { scans: [], lastUpdated: Date.now() },
    customKeywords: [
      'secret', 'api_key', 'password', 'token', 'aws', 'private', 
      'admin', 'debug', 'internal', 'jwt', 'oauth', 'bearer', 
      'authorization', 'crypt', 'key', 'credential', 'passwd'
    ],
    extensionVersion: '1.0.0'
  });
});
