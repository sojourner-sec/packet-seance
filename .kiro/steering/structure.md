# Packet Séance — Structure

## Files (no build step, loaded with script tags in this order)
- `index.html` — layout: upload area, sample buttons, spirit board, results, mute toggle
- `style.css` — themes and animations
- `samples.js` — functions that generate the 3 sample captures as bytes
- `pcap.js` — pcap reader and packet decoder (pure functions)
- `detectors.js` — detection rules and severity (pure functions)
- `story.js` — ghost-story, explanation and defender-tip templates (pure functions)
- `audio.js` — Web Audio synthesizer and mute control
- `app.js` — state machine (idle, summoning, calm, strike), UI wiring, reset and cleanup

## Repository rules
- Public repo with MIT license
- `.kiro/` (steering, specs, hooks) MUST be committed and never added to `.gitignore`
- Keep a short README with: what it is, how to run it, how to capture a pcap, and the Kiro features used
- Each module exposes plain global functions with clear names, so teammates can work on different files without merge conflicts