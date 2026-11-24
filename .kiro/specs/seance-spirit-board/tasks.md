# Implementation Plan: Séance Spirit-Board Log Analyzer

## Overview

Build the complete single-page Séance app in three flat files (`index.html`, `style.css`, `app.js`). Tasks follow the user-specified order: layout → analyzer → spirit board → state machine → audio → strike/reveal → reset → testing. Each task is a concrete coding step; every step builds on the previous one so nothing is left orphaned.

## Tasks

- [x] 1. Scaffold HTML layout and sample logs
  - [x] 1.1 Write `index.html` skeleton with all required sections
    - Add `<textarea>` for log input and a "Summon Diagnosis" `<button>`
    - Add three sample-log `<button>` elements (IDs: `sample-a`, `sample-b`, `sample-c`)
    - Add a result panel `<div id="result-panel">` with placeholders for surface and hidden findings
    - Add a Mute/Unmute `<button id="mute-btn">` fixed to a corner
    - Add a Reset `<button id="reset-btn">`
    - Link `style.css` and `app.js` (deferred)
    - _Requirements: 1.1, 1.2, 2.1, 6.1, 8.4, 9.1_
    - _Design: UI Layer, Components and Interfaces §4_

  - [x] 1.2 Write base `style.css` Victorian dark-séance theme
    - Set CSS custom properties for brass, aged-parchment, candlelight palette
    - Apply a serif font (Google Font with safe fallback)
    - Style the textarea, buttons, result panel, and mute/reset controls
    - Add `[data-phase]` selectors so CSS responds to `body[data-phase="summoning"]`, `calm`, `strike`, `idle`
    - Add `.parchment-mode` class that switches to the daylight palette
    - _Requirements: 5.1, 5.2, 10.1, 10.3_
    - _Design: UI Layer §4_

  - [x] 1.3 Define the three sample logs in `app.js` under `// --- SAMPLE LOGS ---`
    - Sample A: contains an exposed token (triggers strike)
    - Sample B: contains `DROP TABLE` (triggers strike)
    - Sample C: contains only a `ReferenceError` with no critical pattern (no strike)
    - Implement `fillTextarea(sampleText)` UI helper and wire the three sample buttons to it
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
    - _Design: UI Layer §4, `fillTextarea`_

- [x] 2. Implement the log analyzer (pure functions)
  - [x] 2.1 Implement `analyzeSurface(logText)` under `// --- ANALYZER ---`
    - Check patterns in priority order: `ReferenceError`, `Cannot read propert`, `Uncaught`, `Maximum call stack`, `timeout|ETIMEDOUT`, then generic fallback
    - Return a `SurfaceFinding` object `{ type, label, matchedText }`
    - _Requirements: 3.1, 3.4, 3.5_
    - _Design: Analyzer §1, `analyzeSurface`, Data Models_

  - [ ]* 2.2 Write property test for `analyzeSurface` — Property 1
    - **Property 1: Surface finding is always present**
    - **Validates: Requirements 3.1, 3.4**
    - Use fast-check; generate arbitrary non-empty strings; assert `label` and `type` are non-empty strings

  - [x] 2.3 Implement `analyzeHidden(logText)` under `// --- ANALYZER ---`
    - Test patterns in priority order: exposed credential token, `password=`, `eval(`, `DROP TABLE`, `CRITICAL|FATAL`
    - Return `HiddenFinding { type, matchedText, severity, remediation }` or `null`
    - Wrap each regex in try/catch; degrade gracefully to `null` on exception
    - _Requirements: 3.2, 3.3, 3.5_
    - _Design: Analyzer §1, `analyzeHidden`, Error Handling_

  - [ ]* 2.4 Write property tests for `analyzeHidden` — Properties 2 and 3
    - **Property 2: Hidden scan returns null for safe logs**
    - **Validates: Requirements 3.2, 7.6**
    - **Property 3: Hidden scan detects all critical patterns**
    - **Validates: Requirements 3.2, 3.3**
    - Use fast-check; generate safe strings (no critical substrings) and assert `null`; inject each critical pattern substring and assert non-null with correct `type`

  - [x] 2.5 Implement `buildSuggestedFix(finding)` under `// --- ANALYZER ---`
    - Return a human-readable one-sentence fix string for each `SurfaceFinding.type`
    - _Requirements: 3.1, 6.1_
    - _Design: Analyzer §1, `buildSuggestedFix`_

  - [x] 2.6 Implement `analyzeLog(logText)` as the public entry point
    - Trims input; returns `null` if whitespace-only (caller handles the error message)
    - Calls `analyzeSurface` and `analyzeHidden`; returns `AnalysisResult { surface, hidden }`
    - _Requirements: 1.3, 3.1, 3.2_
    - _Design: Data Models, Error Handling §empty-or-whitespace_

  - [ ]* 2.7 Write property test for whitespace rejection — Property 6
    - **Property 6: Whitespace-only input is rejected**
    - **Validates: Requirements 1.3**
    - Use fast-check; generate strings of only `\s` characters; call `analyzeLog`; assert it returns `null`

- [x] 3. Build the spirit board and planchette
  - [~] 3.1 Add spirit board HTML to `index.html`
    - Create a `<div id="spirit-board">` containing five labelled zone elements: Syntax, Network, Auth, Memory, Secrets/Critical
    - Add `<div id="planchette">` as a child of the board
    - _Requirements: 4.1_
    - _Design: UI Layer §4, `ZONE_POSITIONS`_

  - [~] 3.2 Style the spirit board and planchette in `style.css`
    - Apply Victorian brass and aged-parchment styling to the board
    - Style the planchette with a brass token appearance
    - Use `position: absolute` on the planchette so JS translate moves work
    - _Requirements: 4.1, 10.3_
    - _Design: UI Layer §4_

  - [~] 3.3 Implement `setPlanchetteZone(zone)` in `app.js` under `// --- UI ---`
    - Encode `ZONE_POSITIONS` constant map with the five named positions
    - Apply `transform: translate(x, y)` to the planchette element
    - _Requirements: 4.2, 4.3_
    - _Design: UI Layer §4, `setPlanchetteZone`, `ZONE_POSITIONS`_

  - [~] 3.4 Add planchette walking animation to `style.css`
    - CSS keyframe `@keyframes planchette-walk` with a subtle tremble (small random-feeling translate + rotate steps)
    - Apply animation when `body[data-phase="summoning"]`
    - Add a sharp transition for the slam move (`strike` phase, short duration + ease-in)
    - _Requirements: 4.2, 4.3_
    - _Design: UI Layer §4_

- [ ] 4. Implement the state machine
  - [~] 4.1 Define state object and `setPhase` UI helper under `// --- STATE MACHINE ---`
    - Declare `let state = { phase, result, droneHandle, strikeArmed, strikeTimer, strikeFired }`
    - Implement `setPhase(phase)` that sets `data-phase` attribute on `<body>`
    - _Requirements: 5.1, 5.2, 7.5_
    - _Design: State Machine §3, state object_

  - [~] 4.2 Implement `summon(logText)` transition
    - Guard: if already not in `idle`, return
    - Call `analyzeLog`; if null, call `showEmptyInputMessage()` and return
    - Set `state.result`, arm `strikeArmed` if `hidden !== null`
    - Call `setPhase('summoning')`, `setPlanchetteZone` (cycle through zones), start drone, schedule `_tensionComplete` after ~3 s
    - _Requirements: 1.3, 5.1, 7.6_
    - _Design: State Machine §3, `summon` transition_

  - [~] 4.3 Implement `_tensionComplete()` transition
    - Switch `phase` to `'calm'`
    - Stop drone ramp, call `setPhase('calm')`, add `.parchment-mode` to body
    - Call `showSurfaceFinding(finding, fix)` UI function
    - _Requirements: 5.2, 5.3_
    - _Design: State Machine §3, `_tensionComplete` transition_

  - [~] 4.4 Implement `copyFix()` transition
    - Copy fix text to clipboard using `navigator.clipboard.writeText`; fall back to `execCommand`; fall back to visual selection
    - Call `showCopyConfirmation()`
    - If `strikeArmed`, start 4 s timer calling `_triggerStrike`
    - _Requirements: 6.1, 6.2, 6.3, 7.1_
    - _Design: State Machine §3, `copyFix`; Error Handling §Clipboard_

  - [~] 4.5 Implement `pointerNearInput()` event-to-transition bridge
    - Add `pointermove` listener on the textarea / input area
    - If `strikeArmed && !strikeFired && phase === 'calm'`, call `_triggerStrike()` immediately
    - _Requirements: 7.2_
    - _Design: State Machine §3, `pointerNearInput`_

  - [ ]* 4.6 Write property tests for state machine invariants — Properties 4 and 5
    - **Property 4: Strike fires at most once per analysis run**
    - **Validates: Requirements 7.5**
    - **Property 5: Strike never fires when no hidden pattern exists**
    - **Validates: Requirements 7.6**
    - Simulate repeated `copyFix` calls and `pointerNearInput` events; assert strike count ≤ 1; for null-hidden logs assert strike count = 0

  - [ ]* 4.7 Write property test for reset invariant — Property 7
    - **Property 7: Reset returns to idle from any phase**
    - **Validates: Requirements 9.1, 9.2**
    - Drive state machine to each phase programmatically; call `reset()`; assert `phase === 'idle'`, `strikeFired === false`, `strikeTimer === null`

- [ ] 5. Implement the audio synthesizer
  - [~] 5.1 Implement `initAudio()` under `// --- AUDIO ---`
    - Create `AudioContext` (with `webkitAudioContext` fallback) on first call; store in module variable
    - Create and connect `masterGain` node to `context.destination`
    - If neither API is available, set `audioDisabled = true` and return
    - _Requirements: 8.1, 8.3, 8.5_
    - _Design: Audio Synthesizer §2, `initAudio`, Error Handling §Web Audio API unavailable_

  - [~] 5.2 Implement `playDrone(durationSeconds)` and return a `DroneHandle`
    - Build two oscillators (`sine` ~40 Hz, `sawtooth` ~60 Hz)
    - Feed both through a lowpass `BiquadFilterNode` (cutoff ~200 Hz, Q 5)
    - Apply a linear gain ramp 0 → 0.6 over `durationSeconds`
    - Return `{ stop() }` that ramps gain to 0.0001 over 0.3 s then disconnects
    - _Requirements: 5.1, 8.1, 8.2_
    - _Design: Audio Synthesizer §2, `playDrone`_

  - [~] 5.3 Implement `playSting()`
    - Build three oscillators at dissonant intervals (~440 Hz sawtooth, ~466 Hz sawtooth, ~523 Hz square)
    - Feed through a `WaveShaperNode` with a hard-clip distortion curve
    - Attack 5 ms, exponential decay to 0.0001 over 0.4 s; auto-stop oscillators at 0.5 s
    - _Requirements: 7.3, 8.1, 8.2_
    - _Design: Audio Synthesizer §2, `playSting`_

  - [~] 5.4 Implement `stopAll()` and wire mute toggle
    - `stopAll()`: call `stop()` on any live `DroneHandle`, disconnect remaining nodes
    - Mute-toggle click: toggle `masterGain.gain.value` between `0` and `1`; update button label
    - _Requirements: 8.4, 9.2_
    - _Design: Audio Synthesizer §2, `stopAll`_

- [ ] 6. Implement the strike and hidden-finding reveal
  - [~] 6.1 Implement `_triggerStrike()` transition
    - Guard: `if (state.strikeFired) return;` — set `strikeFired = true` immediately
    - Clear any pending `strikeTimer`
    - Call `setPhase('strike')`, `triggerFlash()`, `playSting()`, `setPlanchetteZone('critical')`
    - After flash resolves, call `showHiddenFinding(state.result.hidden)`
    - _Requirements: 7.3, 7.4, 7.5_
    - _Design: State Machine §3, `_triggerStrike`_

  - [~] 6.2 Implement `triggerFlash()` UI function
    - Add `.invert-flash` class to `<body>`; remove it after 250 ms via `setTimeout`
    - _Requirements: 7.3_
    - _Design: UI Layer §4, `triggerFlash`_

  - [~] 6.3 Add `.invert-flash` CSS rule
    - Apply `filter: invert(1)` to `body.invert-flash` for the 250 ms window
    - _Requirements: 7.3_
    - _Design: UI Layer §4_

  - [~] 6.4 Implement `showSurfaceFinding(finding, fix)` and `showHiddenFinding(finding)` UI functions
    - `showSurfaceFinding`: populate result panel with surface label, matched text, fix string, and "Copy Fix" button
    - `showHiddenFinding`: populate result panel with hidden type, severity badge, matched text (truncated to 80 chars), and remediation
    - _Requirements: 5.3, 7.4_
    - _Design: UI Layer §4, `showSurfaceFinding`, `showHiddenFinding`_

  - [~] 6.5 Implement `showCopyConfirmation()` UI function
    - Briefly display "Copied!" feedback near the "Copy Fix" button; auto-hide after ~1.5 s
    - _Requirements: 6.2_
    - _Design: UI Layer §4, `showCopyConfirmation`_

  - [~] 6.6 Implement `showEmptyInputMessage()` UI function
    - Display an in-theme message: "The spirits find no message here…" in the result panel
    - Do not change `state.phase` (stays in `idle`)
    - _Requirements: 1.3_
    - _Design: Error Handling §empty-or-whitespace_

- [ ] 7. Implement reset and wire all event handlers
  - [~] 7.1 Implement `reset()` transition
    - Clear `strikeTimer` via `clearTimeout`
    - Call `stopAll()`
    - Reset all state fields to defaults
    - Call `setPhase('idle')`, remove `.parchment-mode`, clear result panel content
    - _Requirements: 9.1, 9.2_
    - _Design: State Machine §3, `reset` transition_

  - [~] 7.2 Wire all UI event handlers under `// --- UI ---`
    - "Summon Diagnosis" button → `initAudio()` then `summon(textarea.value)`
    - "Copy Fix" button → `copyFix()`
    - Reset button → `reset()`
    - Textarea `pointermove` → `pointerNearInput()`
    - Mute button → mute-toggle logic (already in `stopAll` section; just wire the DOM event)
    - Sample buttons A/B/C → `fillTextarea(sampleText)`
    - _Requirements: 1.2, 2.2, 6.1, 7.2, 8.4, 9.1_
    - _Design: UI Layer §4_

  - [~] 7.3 Checkpoint — Ensure manual smoke test passes
    - Open `index.html` in a browser; paste each sample log and step through the full 3-beat loop
    - Verify parchment mode, flash, sting, planchette slam, and hidden finding all work
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Final testing — property-based and unit tests
  - [~] 8.1 Create `tests/index.html` test runner
    - Load fast-check from CDN (production files have no CDN dependency)
    - Import the testable pure functions from `app.js` (or a shared module) and run all property tests
    - _Requirements: 3.5_
    - _Design: Testing Strategy_

  - [ ]* 8.2 Confirm all seven property tests pass
    - Run the test file in a browser; verify all 7 properties report green (≥ 100 iterations each)
    - Annotate each test with its property tag: `Feature: seance-spirit-board, Property N: …`
    - _Design: Testing Strategy, property-based tests table_

  - [ ]* 8.3 Write unit tests for specific examples
    - Each critical pattern triggers the correct `HiddenFinding.type` (one test per pattern — 5 tests)
    - Fallback surface finding fires when no pattern matches
    - `buildSuggestedFix` returns a non-empty string for every `SurfaceFinding.type`
    - `reset()` from each of the four phases leaves state in the expected shape
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 9.1_
    - _Design: Testing Strategy, unit tests_

  - [~] 8.4 Final checkpoint — All tests pass and app is production-ready
    - Verify static-file hosting works (open via `file://` or a local server with no config)
    - Confirm no external audio files, no build step, relative paths only
    - Ensure all tests pass, ask the user if questions arise.
    - _Requirements: 10.1, 10.2, 10.3_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements and design sections for full traceability
- Checkpoints (7.3, 8.4) ensure incremental validation before moving to the next phase
- Property tests validate universal correctness; unit tests validate specific examples and edge cases
- The test runner (`tests/index.html`) is a dev artifact — it loads fast-check from CDN; the production app has zero external dependencies

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["2.1"] },
    { "id": 3, "tasks": ["2.2", "2.3"] },
    { "id": 4, "tasks": ["2.4", "2.5"] },
    { "id": 5, "tasks": ["2.6"] },
    { "id": 6, "tasks": ["2.7", "3.1"] },
    { "id": 7, "tasks": ["3.2", "3.3"] },
    { "id": 8, "tasks": ["3.4"] },
    { "id": 9, "tasks": ["4.1"] },
    { "id": 10, "tasks": ["4.2"] },
    { "id": 11, "tasks": ["4.3"] },
    { "id": 12, "tasks": ["4.4", "4.5"] },
    { "id": 13, "tasks": ["4.6", "4.7"] },
    { "id": 14, "tasks": ["5.1"] },
    { "id": 15, "tasks": ["5.2", "5.3"] },
    { "id": 16, "tasks": ["5.4"] },
    { "id": 17, "tasks": ["6.1", "6.2", "6.3"] },
    { "id": 18, "tasks": ["6.4", "6.5", "6.6"] },
    { "id": 19, "tasks": ["7.1"] },
    { "id": 20, "tasks": ["7.2"] },
    { "id": 21, "tasks": ["7.3"] },
    { "id": 22, "tasks": ["8.1"] },
    { "id": 23, "tasks": ["8.2", "8.3"] },
    { "id": 24, "tasks": ["8.4"] }
  ]
}
```
