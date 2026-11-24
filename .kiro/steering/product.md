# Packet Séance — Product

Packet Séance is a Victorian spirit-board web app. The user uploads a small packet capture (.pcap) from their own lab, and the app narrates what happened on the wire as a ghost story while flagging suspicious patterns. Built for Kiroween 2026, Frankenstein category: networking, security and storytelling stitched into one tool.

## Purpose
Teach network traffic analysis through narrative. Every finding has three parts: a ghost-story paragraph, a plain-English "what really happened" explanation, and a defender's tip. The spooky design is functional: the planchette shows which kind of activity the analyzer is inspecting, and the false-suspense loop teaches that a calm-looking capture can hide a serious problem.

## Responsible use
For analyzing the user's own lab captures. All analysis happens locally in the browser. No capture ever leaves the machine.

## The 3-beat false-suspense loop
1. **The Fake-Out:** The user uploads a capture (or picks a built-in sample) and presses "Summon Diagnosis". The screen dims, a sub-bass drone rises, and the planchette glides across the board. At peak tension the UI snaps to calm parchment mode and shows a harmless traffic summary (packet count, protocols, top talkers) with a "Copy Summary" button.
2. **The Quiet Lull:** The user relaxes and reads or copies the summary.
3. **The Unscripted Strike:** About 4 seconds after "Copy Summary" is clicked (or when the pointer returns toward the upload area), if a high-severity finding exists, trigger a 250ms color-inversion flash, a sharp sting, and a planchette slam onto CRITICAL BREACH. Then reveal each hidden finding as a ghost story with its explanation and defender's tip.

## Spirit board zones
Recon, DNS, Cleartext, Lateral, Critical Breach.

## Detections (rule-based, no AI, no network calls)
- Port scan (high)
- Cleartext credentials in HTTP or FTP (high)
- ARP spoofing (high)
- Suspicious DNS: long or random-looking names, bursts of NXDOMAIN (high)
- Ping sweep (medium)

## Requirements
- 3 built-in sample captures generated in code, including one clean capture with no strike
- Mute/Unmute toggle in a corner
- The strike fires only when a high-severity finding exists
- No login, no backend, no setup