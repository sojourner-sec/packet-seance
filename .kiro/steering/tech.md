# Packet Séance — Tech

## Stack
- Vanilla HTML, CSS and JavaScript only. No frameworks, no bundler, no npm dependencies.
- Plain script tags loaded in order. No ES module imports (so the app also works when opened from a file).

## Capture handling
- Read the uploaded file with the File API (ArrayBuffer and DataView).
- Support classic pcap only: magic numbers 0xa1b2c3d4 / 0xd4c3b2a1 and the nanosecond variants 0xa1b23c4d / 0x4d3cb2a1, both byte orders.
- Support Ethernet link type only. Support IPv4 for TCP, UDP, ICMP, plus ARP. Count other packets but do not analyze them.
- If the file is pcapng (starts with 0x0a0d0d0a), show a friendly in-theme message explaining how to save as classic pcap.
- Limits: files up to 5 MB and up to 50,000 packets analyzed. Skip malformed packets safely; never throw on bad data.

## Analysis
- Parser and detectors are pure functions: bytes in, plain objects out, no DOM access.
- Detection thresholds live in one clearly named config object so they are easy to tune.
- The story generator is template-based and rule-based. Never call an AI or any external service.

## Audio
- Web Audio API only: oscillators, gain, filters and noise generated in code. No audio files.
- Create the AudioContext only after a user click. The mute toggle silences everything.

## Visuals
- CSS animations and transitions. Dark séance mode and parchment calm mode.
- Both themes MUST keep text readable (minimum 4.5:1 contrast).

## Code rules
- Plain, readable code with short comments.
- Use textContent, not innerHTML, for anything derived from capture data (it is untrusted).

## Deployment
- Static files only (GitHub Pages, Vercel or Netlify). Relative paths.