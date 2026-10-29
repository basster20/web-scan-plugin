# Bug Bounty Hunter — Chrome Extension (v1.1.0)

A Manifest V3 security-scanning extension for bug bounty hunters and web
pentesters. It reads the page you are on — DOM, inline scripts, event
handlers, network responses — and reports leaked secrets, dangerous JavaScript
sinks, CORS misconfigurations and exposed endpoints, each with a severity.

Pure JavaScript, no build step, no CDN, no external dependencies.

## What changed in 1.1

Everything is powered by one shared, tested module (`scan-engine.js`):

- **Shared engine** — the same detection code runs in the content script, the
  popup's JS scanner, and the Node test suite. No more logic that only exists
  inside a message handler.
- **Far more detectors** — see the table below; 18 provider-specific secret
  types were added (OpenAI, Anthropic, Hugging Face, SendGrid, Twilio, npm,
  PyPI, GitLab, Telegram, Slack webhooks, connection strings, URL basic-auth…).
- **False positives cut** — Shannon-entropy gate on generic keys, Luhn check
  on card numbers, placeholder/template rejection (`YOUR_API_KEY_HERE`,
  `${SECRET}`, `password = "password"`), and bare hex strings only count when
  a security label sits on the same line.
- **Real taint analysis** — the old version asked "does this source exist
  *anywhere* on the page?", which marked every sink tainted. Now a source only
  taints a sink within 120 characters of it — and the analysis no longer
  re-scans the whole document per sink (it was ~240 full text scans per page).
- **Cross-source deduplication** — the same secret found in body text, HTML
  source and a fetch response counts once, with hard caps so a chatty SPA
  cannot grow results forever.
- **Line numbers** on credentials, keywords and sinks.
- **CORS checks** — wildcard/foreign `Access-Control-Allow-Origin` combined
  with `Access-Control-Allow-Credentials` on intercepted fetch/XHR responses.
- **Sensitive-path triage** — URL inventory is classified: `/.git`,
  `/.env`, backups, `id_rsa`, source maps, wp-admin, debug endpoints…
- **Fixed bugs** — reports recorded the popup's own URL instead of the scanned
  page; MV3 service workers kill `setInterval`, so cleanup now runs on
  `chrome.alarms`; `web_accessible_resources: ["*"]` (rejected by the Web
  Store, useful to fingerprinters) removed; mutation scanning throttled
  instead of running full regex passes on every DOM change.
- **Nicer UX** — severity badges, toasts instead of blocking `alert()`,
  occurrence counts, path highlighting.

## Detection coverage

| Category | Examples | Severity |
| --- | --- | --- |
| Critical | Private keys, AWS access/secret keys, OpenAI/Anthropic keys, live Stripe keys, SendGrid keys, `.env`/`.git` exposure | critical |
| High | GitHub/GitLab/npm/PyPI/Hugging Face/Slack/Telegram/Twilio tokens, connection-string and URL basic-auth credentials, plaintext passwords, backup files | high |
| Medium | JWTs, bearer tokens, test-mode Stripe keys, Sentry DSNs, labelled API keys, admin/debug endpoints, credentialed CORS wildcard | medium |
| Low / Info | Firebase URLs, source maps, emails, long hex strings with a security label | low/info |
| Sinks | `eval`, string `setTimeout`, `Function`, `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`, jQuery HTML methods, navigation sinks — each with **proximity taint flow** | High/Medium |

Validation rules that keep the noise down:

- **Entropy gate** — generic 32-char keys must have ≥ 3.2 bits/char and mix
  character classes; all-lowercase runs are dropped.
- **Luhn** — credit-card-shaped numbers must pass the checksum.
- **Placeholders** — `YOUR_API_KEY_HERE`, `<token>`, `${VAR}`, `changeme`,
  `password = "password"` and friends are never reported.
- **Hash awareness** — `sha256`/`checksum`/`integrity` context suppresses hex
  findings.

## Installation

1. Open `chrome://extensions/` (Edge: `edge://extensions/`)
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this `bug-bounty-hunter/` folder

## Usage

- **Page Scan** — auto-scans when the popup opens; *Rescan* refreshes.
  Findings are grouped by category with severity badges, masking, line
  numbers and per-finding copy. *Download Report* exports JSON for the page
  you actually scanned.
- **Sinks** — filter by severity or by taint flow; each sink shows its code
  snippet, line, repeat count and the nearby sources.
- **JS Scanner** — paste a snippet or give a `.js` URL. Runs locally in the
  popup via the shared engine, so it works even on pages where content
  scripts cannot run (`chrome://`, Web Store). Custom keywords are
  comma-separated.
- **Settings** — manage keywords (one per line), clear stored data.

## Testing

```bash
node tests/engine.test.js
```

43 assertions covering detection, rejection of noise, dedup caps, taint
proximity, line numbers and path triage. Runs in plain Node, no install.

## Files

```
bug-bounty-hunter/
├── manifest.json      # MV3 manifest
├── scan-engine.js     # shared detection engine (pure, tested)
├── content.js         # DOM/network plumbing, uses the engine
├── background.js      # service worker: aggregation + alarms cleanup
├── popup.html/js      # UI
├── styles.css
├── tests/engine.test.js
└── icons/
```

## Security considerations

- For **security research and authorized testing only**. Do not use on
  systems you do not have permission to test.
- Credential values are masked in the UI; copy buttons expose the full value
  deliberately. Downloaded reports contain unmasked values — handle them
  accordingly.
- The extension needs `activeTab`, `storage`, `scripting` and `alarms`.
  Network interception happens in pages you visit, locally; nothing is sent
  anywhere.

## License

MIT — free for security research and educational use.

## Disclaimer

Provided "as is" for legitimate security research. The authors are not
responsible for misuse. Always obtain proper authorization before testing
any system.
