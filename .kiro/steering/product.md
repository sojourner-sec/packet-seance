# Séance — Product

Séance is a Victorian spirit-board web app that analyzes developer error logs and stack traces. It is built for the Kiroween 2026 hackathon, Costume Contest category.

## Purpose
The spooky design is not decoration. It guides the user's attention to what the analyzer is inspecting and uses misdirection horror to teach that surface-level fixes can hide critical problems.

## Core experience: the 3-beat false-suspense loop
1. **The Fake-Out:** The user pastes a log (or clicks one of 3 sample logs) and presses "Summon Diagnosis". The screen dims, a sub-bass drone rises, and a brass planchette glides across the spirit board. At peak tension the UI snaps to calm parchment mode and shows a harmless surface finding (such as a syntax or formatting issue) with a "Copy Fix" button.
2. **The Quiet Lull:** The user relaxes and copies the minor fix.
3. **The Unscripted Strike:** About 4 seconds after "Copy Fix" is clicked (or when the pointer moves back toward the input area), if the log contains hidden critical patterns, trigger a 250ms color-inversion flash, a sharp sting sound, and a planchette slam onto "CRITICAL BREACH". Then reveal the hidden high-severity issue and its remediation.

## Spirit board zones
Syntax, Network, Auth, Memory, Secrets / Critical. The planchette points at the zone currently being analyzed.

## Hidden critical patterns (trigger the strike)
Exposed API keys or tokens, `password=`, `eval(`, `DROP TABLE`, and critical/fatal stack frames.

## Requirements
- 3 one-click sample haunted logs for instant demos
- Mute/Unmute toggle in a corner
- The scare must only fire when a hidden critical pattern exists
- Must work instantly with no setup, no login, and no backend