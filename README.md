# Packet Séance

A Victorian spirit-board web app that narrates your packet captures as ghost stories while flagging suspicious network activity. Upload a `.pcap` file from your own lab and the séance reveals what happened on the wire — port scans, cleartext credentials, ARP spoofing, DNS tunnelling, and ping sweeps — each wrapped in atmospheric prose with a plain-English explanation and a defender's tip. Built for Kiroween 2026.

All analysis runs entirely in the browser. No capture ever leaves your machine.

## How to run

No build step or server required. Open `index.html` directly in any modern browser:

```
# From the file system (works in Chrome, Edge, Firefox):
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux
```

Or serve with any static file server for a cleaner URL:

```bash
# Python 3
python -m http.server 8080

# Node (npx)
npx serve .
```

Then open `http://localhost:8080` in your browser.

## How to capture a pcap

1. Open **Wireshark** and select your network interface.
2. Click the blue shark-fin button to start capturing.
3. Reproduce the traffic you want to analyze (browse a site, run a ping, etc.).
4. Click the red square to stop.
5. **File → Save As** — choose **Wireshark/tcpdump/... - pcap** (classic pcap, not pcapng).
6. Keep the file under 5 MB (roughly 50,000 packets).

You can also use `tcpdump`:

```bash
sudo tcpdump -i eth0 -w capture.pcap -c 5000
```

## Kiro features used

- **Spec-driven development** — requirements, design, and tasks documents in `.kiro/specs/` drove the full implementation
- **Property-based tests** — `tests/index.html` runs 12 fast-check properties covering the pcap parser, detectors, story generator, and state-machine invariants
- **Steering rules** — `.kiro/` workspace rules enforced vanilla JS, no-build constraints, and security practices (textContent over innerHTML) throughout

## Project structure

| File | Purpose |
|------|---------|
| `index.html` | App shell, spirit board markup, all 6 script tags in order |
| `style.css` | Dark séance and parchment calm themes (WCAG AA throughout) |
| `samples.js` | Three built-in synthetic pcap captures generated in code |
| `pcap.js` | pcap parser and packet decoder (pure functions) |
| `detectors.js` | Five detection rules with configurable thresholds |
| `story.js` | Ghost-story, explanation, and defender-tip templates |
| `audio.js` | Web Audio API synthesizer — no audio files |
| `app.js` | State machine (idle → summoning → calm → strike) and UI wiring |
| `tests/` | Property-based test suite (open `tests/index.html` in a browser) |

## License

MIT — see `LICENSE`.
