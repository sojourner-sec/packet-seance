# Séance — Structure

## Files
- `index.html` — page layout: input area, spirit board, result panel, mute toggle
- `style.css` — all styling, themes (dark séance mode and parchment calm mode) and animations
- `app.js` — log parser, state machine, audio synth, UI logic

## Organization inside app.js
Keep these sections clearly separated with comment headers:
1. Sample logs
2. Log analyzer (surface finding and hidden critical pattern detection)
3. Audio synthesizer
4. 3-beat state machine (idle, summoning, calm, strike)
5. UI event handlers

## Repository rules
- Repo is public with an open-source license (MIT)
- `.kiro/` (steering, specs, hooks) MUST be committed and never added to `.gitignore`
- Keep the project in a single flat folder with no nested build output