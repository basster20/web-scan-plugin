# web-scan-plugin

Two independent tools that live in this repository:

| Folder | What it is |
| --- | --- |
| [`bug-bounty-hunter/`](bug-bounty-hunter/) | Chrome/Edge (MV3) extension that scans the page you are on — and any `.js` file you point it at — for leaked secrets, dangerous sinks, CORS flaws and sensitive endpoints. Pure JavaScript, no build step, no dependencies. |
| [`bible_dual_ndi/`](bible_dual_ndi/) | Python church-presentation tool: voice-driven Bible display with NDI output for OBS/vMix. |

## Quick start — the extension

1. Open `chrome://extensions/` (Edge: `edge://extensions/`)
2. Enable **Developer mode**
3. **Load unpacked** → select the `bug-bounty-hunter/` folder
4. Click the extension icon on any page

Tests (Node 18+, no install needed):

```bash
node bug-bounty-hunter/tests/engine.test.js
```

See [`bug-bounty-hunter/README.md`](bug-bounty-hunter/README.md) for the full feature list.

## Ethics

These tools are for testing systems **you own or have written permission to
test**. See each folder's README for details.

## License

MIT — see [`bug-bounty-hunter/README.md`](bug-bounty-hunter/README.md).
