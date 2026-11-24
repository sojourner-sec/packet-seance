# Requirements Document

## Introduction

Séance is a Victorian spirit-board web app that analyzes developer error logs and stack traces. It uses a 3-beat false-suspense loop: a tense analysis, a calm and harmless surface finding, then a delayed scare that reveals a hidden critical issue. The app is built with vanilla HTML, CSS and JavaScript, synthesizes all audio with the Web Audio API, and runs entirely in the browser.

## Requirements

### Requirement 1: Log Input

**User Story:** As a developer, I want to paste an error log or stack trace, so that Séance can analyze it.

#### Acceptance Criteria

1. THE app SHALL provide a text area where the user can paste a log or stack trace.
2. THE app SHALL provide a "Summon Diagnosis" button that starts the analysis.
3. WHEN the text area is empty AND the user clicks "Summon Diagnosis", THEN THE app SHALL show a short in-theme message asking for a log and SHALL NOT start the analysis.
4. THE app SHALL process all input locally in the browser and SHALL NOT send it to any server.

### Requirement 2: Sample Haunted Logs

**User Story:** As a judge or first-time visitor, I want one-click sample logs, so that I can see the full experience instantly.

#### Acceptance Criteria

1. THE app SHALL provide 3 sample log buttons.
2. WHEN a sample button is clicked, THEN THE app SHALL fill the text area with that sample log.
3. THE samples SHALL each contain a harmless surface issue, AND at least 2 of them SHALL contain a hidden critical pattern.
4. THE samples SHALL include at least one log with no hidden critical pattern, so that the no-strike path can be demonstrated.

### Requirement 3: Two-Stage Log Analysis

**User Story:** As a developer, I want a surface finding and a hidden-issue check, so that I get both a quick fix and a security warning.

#### Acceptance Criteria

1. WHEN analysis runs, THEN THE analyzer SHALL identify one surface-level finding (such as a syntax, formatting or minor error) and a suggested fix.
2. WHEN analysis runs, THEN THE analyzer SHALL separately scan for hidden critical patterns, including exposed API keys or tokens, `password=`, `eval(`, `DROP TABLE`, and critical or fatal stack frames.
3. IF a hidden critical pattern is found, THEN THE analyzer SHALL record its type, the matching text, and a remediation suggestion.
4. IF no surface issue is found, THEN THE analyzer SHALL return a generic harmless finding so the calm beat still occurs.
5. THE analyzer SHALL be implemented as pure functions that take log text and return results without touching the page.

### Requirement 4: Spirit Board and Planchette

**User Story:** As a user, I want a spirit board that shows what the analyzer is inspecting, so that the horror theme communicates real information.

#### Acceptance Criteria

1. THE app SHALL display a Victorian spirit board with 5 zones: Syntax, Network, Auth, Memory and Secrets / Critical.
2. WHEN analysis is running, THEN THE planchette SHALL move between zones with a trembling and gliding animation.
3. WHEN the strike occurs, THEN THE planchette SHALL slam onto the "CRITICAL BREACH" position.

### Requirement 5: Beat 1 — The Fake-Out

**User Story:** As a user, I want a tense build-up that resolves into something mundane, so that I let my guard down.

#### Acceptance Criteria

1. WHEN "Summon Diagnosis" is clicked with valid input, THEN THE app SHALL dim the screen and start a rising sub-bass drone.
2. WHEN the tension peak is reached, THEN THE app SHALL abruptly switch to a calm daylight parchment mode.
3. WHEN the calm mode appears, THEN THE app SHALL display the surface finding and a "Copy Fix" button.

### Requirement 6: Beat 2 and Copy Fix

**User Story:** As a user, I want to copy the suggested fix, so that I can apply it.

#### Acceptance Criteria

1. WHEN "Copy Fix" is clicked, THEN THE app SHALL copy the surface fix text to the clipboard.
2. WHEN the copy succeeds, THEN THE app SHALL show a brief confirmation.
3. IF the clipboard API is unavailable, THEN THE app SHALL fall back to selecting the text so the user can copy it manually.

### Requirement 7: Beat 3 — The Unscripted Strike

**User Story:** As a user, I want a delayed scare that reveals a hidden serious problem, so that I learn not to trust the surface fix alone.

#### Acceptance Criteria

1. WHEN "Copy Fix" is clicked AND a hidden critical pattern was detected, THEN THE app SHALL wait about 4 seconds and then trigger the strike.
2. WHEN the pointer moves back toward the input area during the calm mode AND a hidden critical pattern was detected AND the strike has not yet fired, THEN THE app SHALL trigger the strike.
3. WHEN the strike triggers, THEN THE app SHALL perform a 250ms screen-color inversion flash, play a sharp discordant sting, and slam the planchette onto "CRITICAL BREACH".
4. AFTER the strike, THE app SHALL reveal the hidden issue, its severity, and a remediation fix.
5. THE strike SHALL fire at most once per analysis run.
6. IF no hidden critical pattern was detected, THEN THE app SHALL NOT trigger the strike.

### Requirement 8: Procedural Audio

**User Story:** As a user, I want atmospheric sound without any external files, so that the app loads reliably anywhere.

#### Acceptance Criteria

1. THE app SHALL generate the tension drone and the sting using the Web Audio API only.
2. THE app SHALL NOT load any external audio files.
3. THE app SHALL create the audio context only after a user click.
4. THE app SHALL provide a Mute/Unmute toggle in a corner of the screen that silences all sound immediately.
5. IF the Web Audio API is unavailable, THEN THE app SHALL still work visually without sound.

### Requirement 9: Reset and Repeat Use

**User Story:** As a user, I want to analyze another log after one run, so that I can keep using the app.

#### Acceptance Criteria

1. THE app SHALL provide a way to reset to the initial state and analyze a new log.
2. WHEN reset, THEN THE app SHALL stop all sounds, clear timers, and return to the dark séance theme.

### Requirement 10: Deployment and Compatibility

**User Story:** As a hackathon judge, I want to open the live app and have it work immediately.

#### Acceptance Criteria

1. THE app SHALL consist of `index.html`, `style.css` and `app.js` with no build step.
2. THE app SHALL work when served as static files from GitHub Pages, Vercel or Netlify.
3. THE app SHALL work in current versions of Chrome, Firefox, Safari and Edge, and its layout SHALL remain usable on a laptop screen.