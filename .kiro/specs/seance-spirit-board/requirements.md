# Requirements Document

## Introduction

Packet Séance is a Victorian spirit-board web app that analyzes a small packet capture (.pcap) and narrates it as a ghost story. It uses a 3-beat false-suspense loop: a tense analysis, a calm and harmless traffic summary, then a delayed scare that reveals hidden suspicious activity. It is built with vanilla HTML, CSS and JavaScript, uses rule-based analysis only, synthesizes audio with the Web Audio API, and runs entirely in the browser.

## Requirements

### Requirement 1: Capture Upload

**User Story:** As a learner, I want to upload a capture from my own lab, so that Séance can analyze it.

#### Acceptance Criteria

1. THE app SHALL provide a file picker and a drag-and-drop area for .pcap files.
2. THE app SHALL provide a "Summon Diagnosis" button that starts the analysis.
3. WHEN no capture is loaded AND the user clicks "Summon Diagnosis", THEN THE app SHALL show a short in-theme message asking for a capture and SHALL NOT start the analysis.
4. IF the file is pcapng, THEN THE app SHALL show a friendly message explaining how to save it as classic pcap.
5. IF the file is not a valid pcap, is empty, or is larger than 5 MB, THEN THE app SHALL show a clear in-theme error and SHALL NOT crash.
6. THE app SHALL process the capture locally in the browser and SHALL NOT upload it anywhere.

### Requirement 2: Sample Captures

**User Story:** As a judge or first-time visitor, I want one-click sample captures, so that I can see the full experience instantly.

#### Acceptance Criteria

1. THE app SHALL provide 3 sample buttons that load captures generated in code (no external files).
2. THE samples SHALL be: "The Quiet House" (clean, no strike), "The Knocking Visitor" (port scan and ping sweep), and "The Whispering Wire" (suspicious DNS, cleartext credentials and ARP spoofing).
3. WHEN a sample button is clicked, THEN THE app SHALL load that capture and show its name and packet count.

### Requirement 3: Packet Parsing

**User Story:** As a developer, I want a reliable parser, so that analysis works on real lab captures.

#### Acceptance Criteria

1. THE parser SHALL read classic pcap files in both byte orders, including nanosecond variants.
2. THE parser SHALL decode Ethernet, ARP, IPv4, TCP, UDP, ICMP and DNS fields needed by the detectors.
3. THE parser SHALL skip malformed or truncated packets without throwing, and SHALL count them.
4. THE parser SHALL count packets of unsupported types without analyzing them.
5. THE parser SHALL stop after 50,000 packets and tell the user the capture was truncated.
6. THE parser SHALL be implemented as pure functions that take bytes and return plain objects without touching the page.

### Requirement 4: Detection Rules

**User Story:** As a learner, I want suspicious patterns flagged, so that I learn what attacks look like on the wire.

#### Acceptance Criteria

1. THE detector SHALL flag a port scan (high) WHEN one source sends TCP SYN packets to at least 15 distinct ports on one destination with few or no completed handshakes.
2. THE detector SHALL flag a ping sweep (medium) WHEN one source sends ICMP echo requests to at least 10 distinct hosts.
3. THE detector SHALL flag suspicious DNS (high) WHEN query names are unusually long or random-looking, or WHEN one client receives a burst of NXDOMAIN replies.
4. THE detector SHALL flag cleartext credentials (high) WHEN HTTP Basic authorization, HTTP form fields such as `password=`, or FTP USER/PASS commands appear in unencrypted traffic.
5. THE detector SHALL flag ARP spoofing (high) WHEN one IP address is claimed by two or more different MAC addresses.
6. EACH finding SHALL record its type, severity, the hosts involved, a short evidence summary and the packet count.
7. THE thresholds SHALL be kept in one config object so they are easy to tune.
8. THE detectors SHALL be pure functions with no page access.
9. THE app SHALL never display or store a full captured password; credentials SHALL be partially masked in the output.

### Requirement 5: Calm Surface Summary

**User Story:** As a user, I want a clear overview of the capture, so that I understand the basics.

#### Acceptance Criteria

1. THE summary SHALL show total packets, capture duration, protocol breakdown and the top talkers.
2. THE summary SHALL include one harmless-looking observation, even when nothing suspicious exists.
3. THE summary SHALL be shown in calm parchment mode with a "Copy Summary" button.

### Requirement 6: Ghost-Story Narration

**User Story:** As a learner, I want findings told as a ghost story with a clear explanation, so that I remember what each attack looks like.

#### Acceptance Criteria

1. FOR each finding, THE app SHALL show a ghost-story paragraph, a plain-English "what really happened" explanation and a defender's tip.
2. THE story SHALL name the real hosts and ports involved so the story matches the evidence.
3. THE narration SHALL be generated from templates, rule-based, with no AI service or network call.
4. THE story text SHALL be inserted using safe text methods, because capture content is untrusted.
5. IF no suspicious findings exist, THEN THE app SHALL tell a short peaceful story about the quiet network.

### Requirement 7: Spirit Board and Planchette

**User Story:** As a user, I want the board to show what the analyzer is inspecting, so that the theme communicates real information.

#### Acceptance Criteria

1. THE app SHALL display a Victorian spirit board with 5 zones: Recon, DNS, Cleartext, Lateral and Critical Breach.
2. WHEN analysis is running, THEN THE planchette SHALL move between the zones with a trembling and gliding animation.
3. WHEN the strike occurs, THEN THE planchette SHALL slam onto Critical Breach.
4. AFTER the strike, THE zones with findings SHALL be visibly highlighted.

### Requirement 8: Beat 1 — The Fake-Out

**User Story:** As a user, I want a tense build-up that resolves into something mundane, so that I let my guard down.

#### Acceptance Criteria

1. WHEN "Summon Diagnosis" is clicked with a valid capture, THEN THE app SHALL dim the screen and start a rising sub-bass drone.
2. WHEN the tension peak is reached, THEN THE app SHALL abruptly switch to calm daylight parchment mode.
3. WHEN calm mode appears, THEN THE app SHALL show the surface summary and the "Copy Summary" button.

### Requirement 9: Beat 2 — Copy Summary

**User Story:** As a user, I want to copy the summary, so that I can keep it.

#### Acceptance Criteria

1. WHEN "Copy Summary" is clicked, THEN THE app SHALL copy the summary text to the clipboard and show a brief confirmation.
2. IF the clipboard API is unavailable, THEN THE app SHALL fall back to selecting the text so the user can copy it manually.

### Requirement 10: Beat 3 — The Unscripted Strike

**User Story:** As a user, I want a delayed scare that reveals hidden serious problems, so that I learn not to trust a calm-looking capture.

#### Acceptance Criteria

1. WHEN "Copy Summary" is clicked AND at least one high-severity finding exists, THEN THE app SHALL wait about 4 seconds and then trigger the strike.
2. WHEN the pointer moves back toward the upload area during calm mode AND a high-severity finding exists AND the strike has not yet fired, THEN THE app SHALL trigger the strike.
3. WHEN the strike triggers, THEN THE app SHALL perform a 250ms color-inversion flash, play a sharp discordant sting and slam the planchette onto Critical Breach.
4. AFTER the strike, THE app SHALL reveal every finding with its ghost story, explanation and defender's tip.
5. THE strike SHALL fire at most once per analysis run.
6. IF no high-severity finding exists, THEN THE app SHALL NOT trigger the strike and SHALL still reveal any medium findings gently.

### Requirement 11: Procedural Audio

**User Story:** As a user, I want atmospheric sound without any external files, so that the app loads reliably anywhere.

#### Acceptance Criteria

1. THE app SHALL generate the drone and sting using the Web Audio API only, with no external audio files.
2. THE app SHALL create the audio context only after a user click.
3. THE app SHALL provide a Mute/Unmute toggle in a corner that silences all sound immediately.
4. IF the Web Audio API is unavailable, THEN THE app SHALL still work visually without sound.

### Requirement 12: Reset and Cleanup

**User Story:** As a user, I want to analyze another capture, so that I can keep using the app.

#### Acceptance Criteria

1. THE app SHALL provide a way to reset and analyze a new capture.
2. WHEN reset or when a new analysis starts, THEN THE app SHALL cancel pending timers, stop all sounds, remove any inversion flash, restore the dark séance theme, clear previous results and reset the strike-fired flag.

### Requirement 13: Deployment and Compatibility

**User Story:** As a hackathon judge, I want to open the live app and have it work immediately.

#### Acceptance Criteria

1. THE app SHALL consist of static files with no build step.
2. THE app SHALL work when served from GitHub Pages, Vercel or Netlify.
3. THE app SHALL work in current Chrome, Firefox, Safari and Edge on a laptop screen.
4. BOTH themes SHALL keep all text readable.