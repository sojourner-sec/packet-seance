# Implementation Plan: Packet Séance — pcap Analyzer

## Overview

Migrate the Séance app from a text-log analyzer to a full packet-capture analyzer. Existing code in `app.js`, `index.html`, and `style.css` covers the state machine, audio stubs, UI helpers, and Victorian theme. The remaining work is: (a) adding four new pure-function modules (`samples.js`, `pcap.js`, `detectors.js`, `story.js`), (b) moving the audio implementation to `audio.js`, (c) updating the HTML and CSS to match the pcap UI and new zone names, and (d) wiring `app.js` to the pcap pipeline.

## Tasks

- [x] 1. Update `index.html` for pcap UI
  - Replace the `<textarea>` with a file-picker input (`<input type="file" accept=".pcap">`) and a drag-and-drop drop zone `<div id="drop-zone">`
  - Keep the "Summon Diagnosis" button; rename "Copy Fix" to "Copy Summary" (update element ID to `copy-summary-btn`)
  - Rename sample buttons: "The Quiet House", "The Knocking Visitor", "The Whispering Wire"; update `aria-label` attributes to match
  - Rename spirit board zone labels from Syntax/Network/Auth/Memory/Critical to **Recon / DNS / Cleartext / Lateral / Critical Breach**; update `data-zone` attributes accordingly
  - Add `<script>` tags (in load order, after `style.css`): `samples.js`, `pcap.js`, `detectors.js`, `story.js`, `audio.js`, `app.js`
  - Add a `<p id="pcapng-msg">` and `<p id="error-msg">` message element (hidden by default) alongside the existing `#empty-input-msg`
  - Add `<div id="summary-panel">` and `<div id="findings-list">` inside `#result-panel` for the calm summary and strike reveal respectively
  - _Requirements: 1.1, 2.2, 7.1, 8.3_

- [x] 2. Update `style.css` for new zone names and contrast
  - Update any CSS comments or selectors that reference the old zone names (syntax, network, auth, memory) to the new names (recon, dns, cleartext, lateral)
  - Verify that both dark-séance and parchment themes maintain ≥ 4.5:1 contrast for all text elements (no code changes needed if they already pass; add a comment confirming the check)
  - Add drop-zone styles: dashed brass border, hover highlight, and an active drag-over state (`#drop-zone.drag-over`)
  - Add `#summary-panel` and `#findings-list` layout styles consistent with the existing `.finding` card pattern
  - _Requirements: 7.1, 7.4, 13.4_

- [ ] 3. Create `samples.js` — three synthetic pcap generators
  - [ ] 3.1 Implement `generateQuietHouseCapture()` → `ArrayBuffer`
    - Write a minimal valid classic pcap (magic `0xa1b2c3d4`, little-endian) with Ethernet link type
    - Include ARP, DNS, and simple HTTP packets; no patterns that trigger any detector
    - _Requirements: 2.1, 2.2_

  - [ ] 3.2 Implement `generateKnockingVisitorCapture()` → `ArrayBuffer`
    - Build TCP SYN packets from one source to 20 distinct destination ports (triggers port scan) and ICMP echo requests to 12 distinct hosts (triggers ping sweep)
    - _Requirements: 2.1, 2.2, 4.1, 4.2_

  - [ ] 3.3 Implement `generateWhisperingWireCapture()` → `ArrayBuffer`
    - Build suspicious DNS queries (names > 40 chars with high Shannon entropy, 12 NXDOMAIN replies), an HTTP request with an `Authorization: Basic` header (credential masked in output), and ARP replies claiming one IP from two different MACs
    - _Requirements: 2.1, 2.2, 4.3, 4.4, 4.5_

- [ ] 4. Create `pcap.js` — packet parser
  - [ ] 4.1 Implement `parsePcap(arrayBuffer)` file-header reader
    - Detect all four magic numbers; detect pcapng magic and throw `{ type: 'PCAPNG' }`; throw `{ type: 'INVALID' }` for unrecognised magic
    - Stop after 50,000 packets (`truncated: true`); skip packets whose `inclLen` reads past the buffer (increment `skipped`); never throw on bad data
    - _Requirements: 3.1, 3.3, 3.5, 1.4_

  - [ ]* 4.2 Write property test for `parsePcap` — Properties 1, 2, 3, 4
    - **Property 1: Parser handles all supported magic numbers** — Validates: Requirements 3.1
    - **Property 2: Parser rejects pcapng** — Validates: Requirements 1.4
    - **Property 3: Malformed packets are skipped safely** — Validates: Requirements 3.3
    - **Property 4: Parser truncates at 50,000 packets** — Validates: Requirements 3.5

  - [ ] 4.3 Implement `decodePacket(rawBytes, linkType, tsSeconds, tsNanoseconds)`
    - Decode Ethernet → ARP or IPv4 → TCP/UDP/ICMP; decode DNS when src/dst port is 53
    - Return the `DecodedPacket` shape from the design; set `protocol: 'unknown'` for unsupported link types or EtherTypes
    - _Requirements: 3.2, 3.4_

  - [ ] 4.4 Implement `buildSummary(packets)`
    - Aggregate total packets, duration, protocol counts, and top-5 talkers
    - _Requirements: 5.1_

- [ ] 5. Create `detectors.js` — detection rules
  - [ ] 5.1 Define `THRESHOLDS` config object with all six threshold constants from the design
    - `portScanMinPorts`, `portScanMaxHandshakeRatio`, `pingSweepMinHosts`, `dnsNxdomainBurst`, `dnsLongNameLength`, `dnsHighEntropy`, `arpSpoofMinMacs`
    - _Requirements: 4.7_

  - [ ] 5.2 Implement `detectPortScan(packets)` → `Finding | null`
    - Group TCP SYN-only packets by src→dst pair; return a high-severity finding if distinct ports ≥ `portScanMinPorts` and handshake ratio ≤ `portScanMaxHandshakeRatio`
    - _Requirements: 4.1, 4.6_

  - [ ]* 5.3 Write property test for `detectPortScan` — Property 5
    - **Property 5: Port scan detector respects threshold** — Validates: Requirements 4.1

  - [ ] 5.4 Implement `detectPingSweep(packets)` → `Finding | null`
    - Group ICMP echo requests by source; return a medium-severity finding if distinct destination IPs ≥ `pingSweepMinHosts`
    - _Requirements: 4.2, 4.6_

  - [ ] 5.5 Implement `detectSuspiciousDns(packets)` → `Finding | null`
    - Flag long names (> `dnsLongNameLength`), high-entropy names (Shannon H > `dnsHighEntropy`), and NXDOMAIN bursts (≥ `dnsNxdomainBurst` per client); severity: high
    - _Requirements: 4.3, 4.6_

  - [ ] 5.6 Implement `detectCleartextCredentials(packets)` → `Finding | null`
    - Scan TCP payloads for HTTP `Authorization: Basic`, `password=` form fields, and FTP `USER`/`PASS` commands; mask credentials (first ≤ 4 chars + `****`); severity: high
    - _Requirements: 4.4, 4.9_

  - [ ]* 5.7 Write property test for `detectCleartextCredentials` — Property 7
    - **Property 7: Credentials are always masked** — Validates: Requirements 4.9

  - [ ] 5.8 Implement `detectArpSpoofing(packets)` → `Finding | null`
    - Map `ip → Set<mac>` from ARP replies; return a high-severity finding if any IP appears with ≥ `arpSpoofMinMacs` distinct MACs
    - _Requirements: 4.5, 4.6_

  - [ ]* 5.9 Write property test for `detectArpSpoofing` — Property 6
    - **Property 6: ARP spoof detector respects threshold** — Validates: Requirements 4.5

  - [ ] 5.10 Implement `runDetectors(packets)` → `Finding[]`
    - Call all five detectors and return the array of non-null results
    - _Requirements: 4.6, 4.8_

  - [ ]* 5.11 Write property test for finding shape — Property 8
    - **Property 8: Finding shape is complete** — for any non-null finding from any detector, `type`, `severity`, `hosts`, `evidence`, and `packetCount` are all present and non-empty/non-zero
    - **Validates: Requirements 4.6**

- [ ] 6. Create `story.js` — narrative templates
  - [ ] 6.1 Implement `generateSummaryStory(summary)` → `string`
    - Return a short harmless ghost-story paragraph referencing real protocol counts and packet totals; always return a non-empty string
    - _Requirements: 5.2, 6.3_

  - [ ] 6.2 Implement `generateFindingStory(finding)` → `{ story, explanation, tip }`
    - Template-driven narration for all five finding types; name real hosts from `finding.hosts`; all three fields must always be non-empty strings
    - _Requirements: 6.1, 6.2, 6.4_

  - [ ]* 6.3 Write property test for story functions — Property 9 and Property 12
    - **Property 9: Story functions always return non-empty strings** — `generateSummaryStory` and `generatePeacefulStory` always return non-empty strings; `generateFindingStory` returns all three non-empty fields for each known type
    - **Property 12: `generateFindingStory` returns non-empty strings for all five finding types**
    - **Validates: Requirements 5.2, 6.1, 6.5**

  - [ ] 6.4 Implement `generatePeacefulStory(summary)` → `string`
    - Return a short peaceful story for a clean capture with no findings; always a non-empty string
    - _Requirements: 6.5_

- [ ] 7. Create `audio.js` — full audio synthesizer
  - [ ] 7.1 Move `initAudio()` from `app.js` to `audio.js`; keep the same signature and fallback logic
    - Delete the stub in `app.js` once `audio.js` is loaded via script tag before `app.js`
    - _Requirements: 11.1, 11.2, 11.4_

  - [ ] 7.2 Implement `playDrone(durationSeconds)` → `DroneHandle` in `audio.js`
    - Two oscillators (`sine` ~40 Hz, `sawtooth` ~60 Hz) → `BiquadFilterNode` (lowpass 200 Hz, Q 5) → gain ramp 0 → 0.6
    - Return `{ stop() }` that ramps gain to 0.0001 over 0.3 s then disconnects
    - Remove the stub from `app.js`
    - _Requirements: 8.1, 11.1_

  - [ ] 7.3 Implement `playSting()` in `audio.js`
    - Three oscillators at ~440 Hz (sawtooth), ~466 Hz (sawtooth), ~523 Hz (square) → `WaveShaperNode` (hard-clip) → gain (5 ms attack, exponential decay to 0.0001 over 0.4 s); auto-stop at 0.5 s
    - Remove the stub from `app.js`
    - _Requirements: 10.3, 11.1_

  - [ ] 7.4 Implement `stopAll()` and `setMute(muted)` in `audio.js`
    - `stopAll()`: stop any live DroneHandle and disconnect remaining nodes
    - `setMute(muted)`: set `masterGain.gain.value` to 0 or 1
    - Remove stub from `app.js`; update mute-button handler in `app.js` to call `setMute()`
    - _Requirements: 11.3, 12.2_

- [ ] 8. Update `app.js` — pcap pipeline and UI wiring
  - [ ] 8.1 Expand state object with `packets`, `summary`, and `findings` fields
    - Add `packets: null`, `summary: null`, `findings: []` alongside existing fields
    - _Requirements: 10.5, 10.6, 12.2_

  - [ ] 8.2 Implement file-load entry point: `FileReader` + File API
    - Read the selected or dropped `.pcap` file as `ArrayBuffer` via `FileReader.readAsArrayBuffer`
    - Check `byteLength` ≤ 5 MB before parsing; call `showErrorMessage()` if too large
    - Call `summon(arrayBuffer)` on success
    - Wire `<input type="file">` `change` event and `#drop-zone` drag-and-drop events (`dragenter`, `dragover`, `dragleave`, `drop`)
    - _Requirements: 1.1, 1.5_

  - [ ] 8.3 Rewrite `summon(arrayBuffer)` to use the pcap pipeline
    - Accept `ArrayBuffer` instead of `logText`
    - Call `parsePcap(arrayBuffer)`; catch `{ type: 'PCAPNG' }` → `showPcapngMessage()`; catch `{ type: 'INVALID' }` → `showErrorMessage(msg)`
    - On success: call `buildSummary(packets)`, `runDetectors(packets)`; store into `state`; set `strikeArmed = findings.some(f => f.severity === 'high')`
    - Start planchette walk across recon → dns → cleartext → lateral zones
    - _Requirements: 1.2, 3.1, 3.5, 4.1–4.5, 8.1_

  - [ ] 8.4 Rename `copyFix()` to `copySummary()` and update to copy summary text
    - Read summary text from `#summary-panel` instead of `#surface-fix`
    - Arm the 4 s strike timer if `strikeArmed`
    - Update the DOMContentLoaded handler to listen on `#copy-summary-btn`
    - _Requirements: 9.1, 9.2, 10.1_

  - [ ] 8.5 Rewrite `_tensionComplete()` to call `showSummary()`
    - After stopping the drone and switching to parchment mode, call `showSummary(state.summary, storyText)` where `storyText` comes from `generateSummaryStory(state.summary)`
    - _Requirements: 8.2, 8.3_

  - [ ] 8.6 Implement `showSummary(summary, storyText)` UI function
    - Populate `#summary-panel` with packet count, duration, protocol breakdown, top talkers, and the story paragraph — all via `textContent`
    - Show `#result-panel` and the "Copy Summary" button
    - _Requirements: 5.1, 5.2, 5.3_

  - [ ] 8.7 Implement `showFindings(findings)` UI function for the strike reveal
    - For each finding call `generateFindingStory(finding)` and render story, explanation, and tip into `#findings-list` using `textContent`
    - If `findings` is empty, call `generatePeacefulStory(state.summary)` and show it instead
    - _Requirements: 6.1, 10.4, 10.6_

  - [ ] 8.8 Implement `showPcapngMessage()` and `showErrorMessage(msg)` UI functions
    - `showPcapngMessage()`: reveal `#pcapng-msg` with in-theme instructions for exporting to classic pcap; auto-hide after 6 s
    - `showErrorMessage(msg)`: reveal `#error-msg` with the provided message; auto-hide after 5 s
    - Both keep `state.phase === 'idle'`
    - _Requirements: 1.4, 1.5_

  - [ ] 8.9 Update `_triggerStrike()` to call `showFindings()` after the flash
    - Replace the existing `showHiddenFinding(state.result.hidden)` call with `showFindings(state.findings)`
    - _Requirements: 10.3, 10.4_

  - [ ] 8.10 Update `reset()` to clear new state fields and hide new panels
    - Clear `packets`, `summary`, `findings`; hide `#summary-panel`, `#findings-list`, `#pcapng-msg`, `#error-msg`
    - _Requirements: 12.1, 12.2_

  - [ ] 8.11 Update `loadSampleCapture(name, buffer)` wiring for the three pcap sample buttons
    - Wire "The Quiet House" → `generateQuietHouseCapture()`, "The Knocking Visitor" → `generateKnockingVisitorCapture()`, "The Whispering Wire" → `generateWhisperingWireCapture()`
    - Show capture name and packet count after loading
    - _Requirements: 2.1, 2.2, 2.3_

- [ ] 9. Checkpoint — Smoke test the full 3-beat loop
  - Ensure all tests pass, ask the user if questions arise.
  - Open `index.html` in a browser; verify: file picker, drag-and-drop, all three sample captures, planchette walk, parchment flip, copy summary, 4 s timer, pointer trigger, flash + sting + planchette slam, findings reveal, mute toggle, reset

- [ ] 10. Property-based tests (optional)
  - [ ]* 10.1 Write tests for Properties 1–4 (parsePcap invariants)
    - **Property 1: Parser handles all supported magic numbers** — Validates: Requirements 3.1
    - **Property 2: Parser rejects pcapng** — Validates: Requirements 1.4
    - **Property 3: Malformed packets are skipped safely** — Validates: Requirements 3.3
    - **Property 4: Parser truncates at 50,000 packets** — Validates: Requirements 3.5

  - [ ]* 10.2 Write tests for Properties 5–8 (detector invariants)
    - **Property 5: Port scan detector respects threshold** — Validates: Requirements 4.1
    - **Property 6: ARP spoof detector respects threshold** — Validates: Requirements 4.5
    - **Property 7: Credentials are always masked** — Validates: Requirements 4.9
    - **Property 8: Finding shape is complete** — Validates: Requirements 4.6

  - [ ]* 10.3 Write tests for Properties 9–12 (story and state-machine invariants)
    - **Property 9: Story functions always return non-empty strings** — Validates: Requirements 5.2, 6.1, 6.5
    - **Property 10: Strike fires at most once per analysis run** — Validates: Requirements 10.5
    - **Property 11: Strike never fires without a high-severity finding** — Validates: Requirements 10.6
    - **Property 12: Reset returns to idle from any phase** — Validates: Requirements 12.2

  - [ ]* 10.4 Create `tests/index.html` test runner
    - Load fast-check from CDN; import and run all property tests in one page
    - _Requirements: 3.6_

- [ ] 11. Final checkpoint — All tests pass and app is production-ready
  - Ensure all tests pass, ask the user if questions arise.
  - Verify static-file hosting: open via `file://` and confirm no missing-script errors
  - Confirm all script tags load in correct order, no ES module imports, no external audio files
  - Verify both themes pass 4.5:1 contrast check
  - _Requirements: 13.1, 13.2, 13.3, 13.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- `[x]` tasks are fully implemented in existing code and require no changes
- `[~]` tasks have a working stub or partial implementation that needs updating for the pcap pipeline
- `[ ]` tasks have no existing implementation
- All DOM writes for capture-derived data use `textContent`, never `innerHTML`
- The `tests/index.html` runner loads fast-check from CDN; the production app has zero external dependencies

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "2"] },
    { "id": 1, "tasks": ["3.1", "3.2", "3.3"] },
    { "id": 2, "tasks": ["4.1", "4.3"] },
    { "id": 3, "tasks": ["4.2", "4.4"] },
    { "id": 4, "tasks": ["5.1"] },
    { "id": 5, "tasks": ["5.2", "5.4", "5.5", "5.6", "5.8"] },
    { "id": 6, "tasks": ["5.3", "5.7", "5.9", "5.10"] },
    { "id": 7, "tasks": ["5.11", "6.1", "6.2", "6.4"] },
    { "id": 8, "tasks": ["6.3", "7.1", "7.2", "7.3", "7.4"] },
    { "id": 9, "tasks": ["8.1"] },
    { "id": 10, "tasks": ["8.2", "8.3", "8.5", "8.6", "8.7", "8.8"] },
    { "id": 11, "tasks": ["8.4", "8.9", "8.10", "8.11"] },
    { "id": 12, "tasks": ["9"] },
    { "id": 13, "tasks": ["10.1", "10.2", "10.3"] },
    { "id": 14, "tasks": ["10.4"] },
    { "id": 15, "tasks": ["11"] }
  ]
}
```
