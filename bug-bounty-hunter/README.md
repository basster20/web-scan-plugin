# Bug Bounty Hunter - Chrome Extension

A production-ready web extension for bug bounty hunters that scans webpages for sensitive data, leaked credentials, dangerous JavaScript sinks, and potential security vulnerabilities.

## Features

### Core Scanning Features

1. **Sensitive Keywords Detection**
   - Detects keywords like: admin, password, secret, token, api_key, internal, debug, jwt, oauth, aws_secret, private key, passwd, etc.

2. **Leaked Credentials Detection**
   - Email addresses
   - API keys (generic 32-40 char, AWS, GitHub, Slack, Stripe, Google patterns)
   - Tokens (Bearer, JWT, long hex strings)
   - Passwords in plaintext
   - Credit card numbers
   - Private keys (RSA, SSH)

3. **URL Path Extraction**
   - Extracts paths from `<a href>`, `action="/path"`, `data-url` attributes
   - Includes current window.location paths

4. **Sensitive Cookies**
   - Lists cookies containing "session", "token", "auth", "jwt"

5. **Form Endpoint Analysis**
   - Reports method, action URL, and input names for all forms

6. **Hardcoded JS Variables**
   - Detects variables like `var apiKey = "..."`, `const secret = "..."`

7. **Dangerous Sinks Detection**
   - Code execution: `eval()`, `setTimeout/setInterval` with strings, `Function()`, `execScript`
   - DOM manipulation: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
   - jQuery sinks: `.html()`, `.append()`, `.after()`, `.before()`
   - Navigation: `location.href`, `location.assign`, `location.replace`
   - Messaging: `postMessage()`, `chrome.runtime.sendMessage`
   - Taint flow analysis to identify potential XSS vectors

### JS File Scanner

- Paste raw JavaScript code OR provide a URL to a .js file
- Custom editable keywords (stored in chrome.storage.local)
- Line-by-line keyword matching with context
- Automatic credential regex scanning
- Scrollable results with copy buttons

## Installation

1. Open Chrome/Edge and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `bug-bounty-hunter` folder
5. The extension icon will appear in your toolbar

## Usage

### Page Scan Tab
- Automatically scans the current page when you open the popup
- Click "Rescan" to refresh results
- View findings organized by category
- Click "Download Report" to export results as JSON

### Sinks Tab
- View all detected dangerous JavaScript sinks
- Filter by severity (High/Medium)
- Toggle "Show Taint Flow Only" to see sinks with potential user input sources
- Each sink shows code snippet, context, and potential data sources

### JS Scanner Tab
- Choose between "Code Snippet" or "URL to .js File"
- Paste JavaScript code or enter a URL (CORS permitting)
- Customize keywords (comma-separated)
- Click "Scan JavaScript" to analyze
- Results show line numbers, matched keywords, credentials, and sinks

### Settings Tab
- Manage custom keywords (one per line)
- Save or reset keywords to defaults
- Clear stored scan data
- Extension information

## Files Structure

```
bug-bounty-hunter/
├── manifest.json      # Extension manifest (MV3)
├── background.js      # Service worker for message handling
├── content.js         # Content script for page scanning
├── popup.html         # Popup UI structure
├── popup.js           # Popup logic and UI handling
├── styles.css         # Popup styling
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md          # This file
```

## Technical Details

- **Manifest Version**: 3
- **Permissions**: activeTab, storage, scripting
- **No external dependencies**: Pure JavaScript, no CDNs
- **Efficient regex patterns**: Designed to avoid catastrophic backtracking
- **MutationObserver**: Scans dynamically added content
- **Fetch/XHR patching**: Captures and scans network response bodies
- **Storage**: Results cached in chrome.storage.local

## Regex Patterns

All patterns are optimized for efficiency:

- **Email**: RFC 5322 simplified
- **AWS Keys**: AKIA prefix pattern
- **GitHub Tokens**: ghp_, gho_, ghu_, ghs_, ghr_ prefixes
- **Slack Tokens**: xoxb-, xoxp-, xoxa- prefixes
- **Stripe Keys**: sk_live_, pk_live_, sk_test_, pk_test_ prefixes
- **Google API Keys**: AIza prefix
- **JWT**: eyJ base64url encoded format
- **Private Keys**: BEGIN/END PRIVATE KEY blocks

## Security Considerations

- This extension is for **security research and bug bounty hunting only**
- Do not use on systems you don't have permission to test
- Credentials are masked in the UI but can be copied for verification
- Downloaded reports contain unmasked sensitive data - handle securely

## License

MIT License - Free for security research and educational purposes.

## Disclaimer

This tool is provided "as is" for legitimate security research purposes only. The authors are not responsible for any misuse or damages caused by this software. Always obtain proper authorization before testing any system.
