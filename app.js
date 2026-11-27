// =============================================================================
// SÉANCE — Spirit-Board Log Analyzer
// app.js — All application logic, divided into five sections.
// =============================================================================

// --- SAMPLE LOGS ---

/**
 * Sample A: JavaScript error log with an exposed API token AND a ReferenceError.
 * Hidden pattern: exposed credential token (triggers strike).
 * Surface pattern: ReferenceError.
 */
const SAMPLE_A = `[2024-10-31 02:14:07] INFO  Initializing analytics pipeline v3.2.1
[2024-10-31 02:14:07] INFO  Connecting to data warehouse endpoint: https://api.datastream.io/v2
[2024-10-31 02:14:08] DEBUG Authorization header set: Bearer ghp_xK9mLQvR3nTwYZ4aBcDeFgHiJkLmNoPqRsTuV_APIToken
[2024-10-31 02:14:08] INFO  Fetching user cohort batch #441...
[2024-10-31 02:14:09] ERROR ReferenceError: cohortData is not defined
    at processBatch (pipeline.js:88:14)
    at async DataWarehouseClient.fetchCohort (client.js:203:5)
    at async module.exports.run (index.js:47:3)
[2024-10-31 02:14:09] WARN  Retrying batch #441 (attempt 1 of 3)
[2024-10-31 02:14:11] ERROR ReferenceError: cohortData is not defined
    at processBatch (pipeline.js:88:14)
[2024-10-31 02:14:11] ERROR Max retries exceeded. Batch #441 failed permanently.
[2024-10-31 02:14:11] INFO  Pipeline exiting with code 1`;

/**
 * Sample B: Server/database error log with DROP TABLE AND a timeout surface error.
 * Hidden pattern: SQL injection vector (triggers strike).
 * Surface pattern: timeout / ETIMEDOUT.
 */
const SAMPLE_B = `[2024-10-31 03:55:12] INFO  POST /api/reports/generate — user_id=9182
[2024-10-31 03:55:12] DEBUG Query received: SELECT * FROM reports WHERE name = 'Q3'; DROP TABLE reports; --'
[2024-10-31 03:55:13] ERROR connect ETIMEDOUT 10.0.0.42:5432
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1278:16)
    at ConnectionPool._connect (pg-pool/index.js:134:12)
    at ConnectionPool.connect (pg-pool/index.js:76:19)
    at Query.run (db/query.js:55:21)
    at ReportController.generate (controllers/report.js:92:5)
[2024-10-31 03:55:13] WARN  Database connection timed out after 1000ms
[2024-10-31 03:55:13] INFO  Retrying query (attempt 1 of 2)...
[2024-10-31 03:55:15] ERROR connect ETIMEDOUT 10.0.0.42:5432
[2024-10-31 03:55:15] ERROR Report generation failed — returning 503 to client`;

/**
 * Sample C: JavaScript error log with only a ReferenceError — NO critical patterns.
 * No token, no password=, no eval(, no DROP TABLE, no CRITICAL/FATAL.
 * Strike must NOT trigger.
 */
const SAMPLE_C = `[2024-10-31 11:32:04] INFO  Starting dev server on http://localhost:3000
[2024-10-31 11:32:05] INFO  Compiling module graph (243 modules)...
[2024-10-31 11:32:06] INFO  Compilation complete in 1842ms
[2024-10-31 11:32:19] INFO  GET /dashboard — 200 OK (84ms)
[2024-10-31 11:32:21] INFO  GET /api/user/profile — 200 OK (31ms)
[2024-10-31 11:32:23] ERROR Uncaught ReferenceError: chartInstance is not defined
    at renderDashboard (dashboard.js:114:5)
    at HTMLButtonElement.<anonymous> (dashboard.js:88:3)
[2024-10-31 11:32:23] WARN  Component <MetricsChart> failed to mount
[2024-10-31 11:32:23] INFO  Error boundary caught exception — displaying fallback UI
[2024-10-31 11:32:23] INFO  GET /api/metrics — 200 OK (58ms)`;


// --- ANALYZER ---

/**
 * analyzeSurface(logText)
 * Scans a log string for the first recognisable minor/surface-level issue and
 * returns a SurfaceFinding.  Patterns are tested in priority order; a generic
 * fallback fires when none match.
 *
 * @param {string} logText
 * @returns {{ type: string, label: string, matchedText: string }}
 */
function analyzeSurface(logText) {
  const checks = [
    { pattern: /ReferenceError/i,       type: 'ReferenceError',    label: 'Undefined variable reference' },
    { pattern: /Cannot read propert/i,  type: 'NullDereference',   label: 'Null dereference'             },
    { pattern: /Uncaught/i,             type: 'UncaughtException', label: 'Uncaught exception'            },
    { pattern: /Maximum call stack/i,   type: 'StackOverflow',     label: 'Stack overflow'                },
    { pattern: /timeout|ETIMEDOUT/i,    type: 'NetworkTimeout',    label: 'Network timeout'               },
  ];

  const lines = logText.split('\n');

  for (const { pattern, type, label } of checks) {
    for (const line of lines) {
      if (pattern.test(line)) {
        return { type, label, matchedText: line };
      }
    }
  }

  // Generic fallback — always fires so the calm beat can still occur (Req 3.4).
  return { type: 'Generic', label: 'Unexpected runtime error', matchedText: '' };
}


/**
 * analyzeHidden(logText)
 * Scans a log string for critical hidden patterns.  Patterns are tested in
 * priority order; the first match is returned as a HiddenFinding.  Each regex
 * test is wrapped in a try/catch so a pattern failure degrades gracefully.
 * Returns null when no critical pattern is found.
 *
 * @param {string} logText
 * @returns {{ type: string, matchedText: string, severity: 'CRITICAL', remediation: string } | null}
 */
function analyzeHidden(logText) {
  const checks = [
    {
      pattern: /[A-Za-z0-9_]{20,}.*[Kk]ey|[Tt]oken|[Ss]ecret/,
      type: 'ExposedCredential',
      remediation: 'Rotate this credential immediately and move it to environment variables.',
    },
    {
      pattern: /password\s*=/i,
      type: 'HardcodedPassword',
      remediation: 'Use a secrets manager instead of hardcoding passwords.',
    },
    {
      pattern: /eval\s*\(/,
      type: 'UnsafeEval',
      remediation: 'Replace eval() with a safe alternative such as JSON.parse or a sandboxed evaluator.',
    },
    {
      pattern: /DROP\s+TABLE/i,
      type: 'SQLInjection',
      remediation: 'Parameterize all database queries to prevent SQL injection.',
    },
    {
      pattern: /CRITICAL|FATAL/i,
      type: 'CriticalFrame',
      remediation: 'Investigate this stack frame immediately — a fatal condition was detected.',
    },
  ];

  for (const { pattern, type, remediation } of checks) {
    try {
      const match = pattern.exec(logText);
      if (match) {
        return {
          type,
          matchedText: match[0].slice(0, 80),
          severity: 'CRITICAL',
          remediation,
        };
      }
    } catch (_err) {
      // Pattern failed — skip and try the next one.
    }
  }

  return null;
}


/**
 * buildSuggestedFix(finding)
 * Returns a human-readable, one-sentence fix string for the given SurfaceFinding.
 *
 * @param {{ type: string, label: string, matchedText: string }} finding
 * @returns {string}
 */
function buildSuggestedFix(finding) {
  const fixes = {
    ReferenceError:    'Declare the variable before use, or check for a missing import.',
    NullDereference:   'Add a null check or optional chaining (?.) before accessing the property.',
    UncaughtException: 'Wrap the throwing code in a try/catch block and handle the error.',
    StackOverflow:     'Check for unintended recursion and add a base case or depth limit.',
    NetworkTimeout:    'Increase the request timeout or add retry logic with exponential back-off.',
    Generic:           'Review the stack trace above and add targeted error handling.',
  };

  return fixes[finding.type] ?? 'Review the error and add appropriate error handling.';
}


/**
 * analyzeLog(logText)
 * Public entry point for the analyzer.  Trims the input, rejects whitespace-only
 * strings with null, then delegates to analyzeSurface and analyzeHidden.
 *
 * @param {string} logText
 * @returns {{ surface: SurfaceFinding, hidden: HiddenFinding | null } | null}
 *   Returns null when the trimmed input is empty; the caller is responsible for
 *   showing an appropriate error message in that case.
 */
function analyzeLog(logText) {
  const trimmed = logText.trim();
  if (trimmed === '') {
    return null;
  }

  const surface = analyzeSurface(trimmed);
  const hidden  = analyzeHidden(trimmed);

  return { surface, hidden };
}


// --- STATE MACHINE ---

/**
 * Application state.  All mutable runtime data lives here so every transition
 * function reads and writes the same object.
 *
 * @type {{
 *   phase: 'idle'|'summoning'|'calm'|'strike',
 *   result: {surface: object, hidden: object|null}|null,
 *   droneHandle: {stop: () => void}|null,
 *   strikeArmed: boolean,
 *   strikeTimer: ReturnType<typeof setTimeout>|null,
 *   strikeFired: boolean,
 * }}
 */
let state = {
  phase: 'idle',
  result: null,
  droneHandle: null,
  strikeArmed: false,
  strikeTimer: null,
  strikeFired: false,
};

// --- 4.1 ─────────────────────────────────────────────────────────────────────

/**
 * setPhase(phase)
 * Reflects the current app phase as a `data-phase` attribute on <body> so CSS
 * selectors like `body[data-phase="summoning"]` can respond automatically.
 *
 * @param {'idle'|'summoning'|'calm'|'strike'} phase
 */
function setPhase(phase) {
  document.body.dataset.phase = phase;
  state.phase = phase;
}

// --- 4.2 ─────────────────────────────────────────────────────────────────────

/**
 * summon(logText)
 * Entry-point transition: idle → summoning.
 * Validates input, runs the analyzer, starts the drone and planchette walk,
 * then schedules _tensionComplete after ~3 s.
 *
 * @param {string} logText
 */
function summon(logText) {
  if (state.phase !== 'idle') return;

  const result = analyzeLog(logText);
  if (result === null) {
    showEmptyInputMessage();
    return;
  }

  state.result     = result;
  state.strikeArmed  = result.hidden !== null;
  state.strikeFired  = false;
  state.strikeTimer  = null;

  setPhase('summoning');

  // Walk the planchette through every zone in sequence, spaced evenly over 2.4 s,
  // so it appears to scan the board before settling.
  const walkZones = ['syntax', 'network', 'auth', 'memory'];
  const stepMs    = 600;
  walkZones.forEach(function (zone, i) {
    setTimeout(function () { setPlanchetteZone(zone); }, i * stepMs);
  });

  // Start the rising drone.
  state.droneHandle = playDrone(3);

  // Schedule the tension-peak transition (~3 s).
  setTimeout(_tensionComplete, 3000);
}

// --- 4.3 ─────────────────────────────────────────────────────────────────────

/**
 * _tensionComplete()
 * Internal transition: summoning → calm.
 * Called automatically ~3 s after summon().
 */
function _tensionComplete() {
  if (state.phase !== 'summoning') return;

  // Stop the drone gracefully.
  if (state.droneHandle) {
    state.droneHandle.stop();
    state.droneHandle = null;
  }

  setPhase('calm');
  document.body.classList.add('parchment-mode');

  const fix = buildSuggestedFix(state.result.surface);
  showSurfaceFinding(state.result.surface, fix);
}

// --- 4.4 ─────────────────────────────────────────────────────────────────────

/**
 * copyFix()
 * Copies the surface fix text to the clipboard (with two fallback strategies),
 * shows a brief confirmation, then arms a 4 s timer to trigger the strike if a
 * hidden finding was detected.
 */
function copyFix() {
  if (state.phase !== 'calm') return;

  const fixEl = document.getElementById('surface-fix');
  const fixText = fixEl ? fixEl.textContent : '';

  // Primary: async Clipboard API.
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(fixText).then(function () {
      showCopyConfirmation();
    }).catch(function () {
      _fallbackCopy(fixText);
    });
  } else {
    _fallbackCopy(fixText);
  }

  // Arm the delayed strike, but only once per run.
  if (state.strikeArmed && !state.strikeFired && state.strikeTimer === null) {
    state.strikeTimer = setTimeout(_triggerStrike, 4000);
  }
}

/**
 * _fallbackCopy(text)
 * Falls back to execCommand('copy') after creating a transient textarea,
 * then falls back to visually selecting the fix text so the user can Ctrl+C.
 *
 * @param {string} text
 */
function _fallbackCopy(text) {
  try {
    const temp = document.createElement('textarea');
    temp.value = text;
    temp.style.position = 'fixed';
    temp.style.opacity  = '0';
    document.body.appendChild(temp);
    temp.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(temp);
    if (ok) { showCopyConfirmation(); return; }
  } catch (_) {}

  // Last resort: visually select the fix element text.
  const fixEl = document.getElementById('surface-fix');
  if (fixEl) {
    const range = document.createRange();
    range.selectNodeContents(fixEl);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  }
}

// --- 4.5 ─────────────────────────────────────────────────────────────────────

/**
 * pointerNearInput()
 * Triggers an immediate strike when the user moves the pointer back toward the
 * textarea while in calm mode and a hidden finding is armed.
 * Registered as a pointermove listener on the textarea in the UI section.
 */
function pointerNearInput() {
  if (state.strikeArmed && !state.strikeFired && state.phase === 'calm') {
    _triggerStrike();
  }
}

// --- Stubs for tasks 6.x and 7.x ─────────────────────────────────────────────

/**
 * _triggerStrike()
 * Stub — full implementation in task 6.1.
 * Guards via strikeFired so it fires at most once per run.
 */
function _triggerStrike() {
  if (state.strikeFired) return;
  state.strikeFired = true;

  if (state.strikeTimer !== null) {
    clearTimeout(state.strikeTimer);
    state.strikeTimer = null;
  }

  setPhase('strike');
  triggerFlash();
  playSting();
  setPlanchetteZone('critical');

  // Reveal the hidden finding after the flash resolves.
  setTimeout(function () {
    if (state.result && state.result.hidden) {
      showHiddenFinding(state.result.hidden);
    }
  }, 300);
}

/**
 * reset()
 * Stub — full implementation in task 7.1.
 * Resets state and returns body to dark séance theme.
 */
function reset() {
  if (state.strikeTimer !== null) {
    clearTimeout(state.strikeTimer);
  }
  stopAll();

  state.phase       = 'idle';
  state.result      = null;
  state.droneHandle = null;
  state.strikeArmed  = false;
  state.strikeTimer  = null;
  state.strikeFired  = false;

  document.body.dataset.phase = 'idle';
  document.body.classList.remove('parchment-mode');

  const panel = document.getElementById('result-panel');
  if (panel) panel.hidden = true;

  const surfaceDiv = document.getElementById('surface-finding');
  if (surfaceDiv) surfaceDiv.hidden = true;

  const hiddenDiv = document.getElementById('hidden-finding');
  if (hiddenDiv) hiddenDiv.hidden = true;
}


// --- UI ---

/**
 * ZONE_POSITIONS
 * Maps each named spirit-board zone to a percentage-based (x, y) coordinate.
 * These values are used as CSS `transform: translate(x, y)` on #planchette,
 * which is absolutely positioned inside the relatively-positioned #spirit-board.
 * The translate moves the planchette's centre-point to the zone's focal point.
 */
const ZONE_POSITIONS = {
  syntax:   { x: '15%', y: '30%' },
  network:  { x: '35%', y: '55%' },
  auth:     { x: '55%', y: '30%' },
  memory:   { x: '75%', y: '55%' },
  critical: { x: '45%', y: '75%' },
};

/**
 * setPlanchetteZone(zone)
 * Moves the planchette to the named zone by setting its CSS transform.
 * Falls back silently when the zone name is unrecognised or the element is absent.
 *
 * @param {string} zone - One of: 'syntax', 'network', 'auth', 'memory', 'critical'
 */
function setPlanchetteZone(zone) {
  const planchette = document.getElementById('planchette');
  if (!planchette) return;

  const pos = ZONE_POSITIONS[zone];
  if (!pos) return;

  planchette.style.left = '';
  planchette.style.top  = '';
  planchette.style.transform = `translate(calc(${pos.x} - 50%), calc(${pos.y} - 50%))`;
}

/**
 * fillTextarea(sampleText)
 * Sets the value of #log-input to the provided sample text and focuses the textarea.
 *
 * @param {string} sampleText - The sample log string to load.
 */
function fillTextarea(sampleText) {
  const textarea = document.getElementById('log-input');
  if (!textarea) return;
  textarea.value = sampleText;
  textarea.focus();
}

// ─── UI helper stubs (full implementations in tasks 6.4–6.6) ─────────────────

/**
 * showEmptyInputMessage()
 * Reveals the in-theme empty-input notice without changing state.phase.
 * Requirements: 1.3
 */
function showEmptyInputMessage() {
  const msg = document.getElementById('empty-input-msg');
  if (msg) {
    msg.hidden = false;
    // Auto-hide after 3 s.
    setTimeout(function () { msg.hidden = true; }, 3000);
  }
}

/**
 * showSurfaceFinding(finding, fix)
 * Populates the result panel with the surface label, matched text, and fix string.
 * Requirements: 5.3
 *
 * @param {{ type: string, label: string, matchedText: string }} finding
 * @param {string} fix
 */
function showSurfaceFinding(finding, fix) {
  const panel = document.getElementById('result-panel');
  if (panel) panel.hidden = false;

  const surfaceDiv = document.getElementById('surface-finding');
  if (surfaceDiv) surfaceDiv.hidden = false;

  const labelEl = document.getElementById('surface-label');
  if (labelEl) labelEl.textContent = finding.label;

  const matchEl = document.getElementById('surface-match');
  if (matchEl) matchEl.textContent = finding.matchedText || '(no specific line matched)';

  const fixEl = document.getElementById('surface-fix');
  if (fixEl) fixEl.textContent = fix;
}

/**
 * showHiddenFinding(finding)
 * Populates the result panel with the hidden finding, severity badge, and remediation.
 * Requirements: 7.4
 *
 * @param {{ type: string, matchedText: string, severity: string, remediation: string }} finding
 */
function showHiddenFinding(finding) {
  const panel = document.getElementById('result-panel');
  if (panel) panel.hidden = false;

  const hiddenDiv = document.getElementById('hidden-finding');
  if (hiddenDiv) hiddenDiv.hidden = false;

  const severityEl = document.getElementById('hidden-severity');
  if (severityEl) severityEl.textContent = finding.severity;

  const typeEl = document.getElementById('hidden-type');
  if (typeEl) typeEl.textContent = finding.type.replace(/([A-Z])/g, ' $1').trim();

  const matchEl = document.getElementById('hidden-match');
  if (matchEl) matchEl.textContent = finding.matchedText;

  const remEl = document.getElementById('hidden-remediation');
  if (remEl) remEl.textContent = finding.remediation;
}

/**
 * showCopyConfirmation()
 * Briefly shows "Copied!" feedback near the Copy Fix button; auto-hides after 1.5 s.
 * Requirements: 6.2
 */
function showCopyConfirmation() {
  const confirm = document.getElementById('copy-confirm');
  if (!confirm) return;
  confirm.hidden = false;
  setTimeout(function () { confirm.hidden = true; }, 1500);
}

/**
 * triggerFlash()
 * Adds .invert-flash to <body> for 250 ms to produce a sharp visual shock.
 * Requirements: 7.3
 */
function triggerFlash() {
  document.body.classList.add('invert-flash');
  setTimeout(function () {
    document.body.classList.remove('invert-flash');
  }, 250);
}

// ─── Wire all event handlers ──────────────────────────────────────────────────

// Wire sample buttons once the DOM is ready.
document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('sample-a').addEventListener('click', function () {
    fillTextarea(SAMPLE_A);
  });

  document.getElementById('sample-b').addEventListener('click', function () {
    fillTextarea(SAMPLE_B);
  });

  document.getElementById('sample-c').addEventListener('click', function () {
    fillTextarea(SAMPLE_C);
  });

  // Summon Diagnosis button (task 4.2 / 7.2)
  document.getElementById('summon-btn').addEventListener('click', function () {
    const textarea = document.getElementById('log-input');
    initAudio();
    summon(textarea ? textarea.value : '');
  });

  // Copy Fix button (task 4.4 / 7.2)
  document.getElementById('copy-fix-btn').addEventListener('click', function () {
    copyFix();
  });

  // Reset button (task 7.2)
  document.getElementById('reset-btn').addEventListener('click', function () {
    reset();
  });

  // Mute / Unmute toggle — delegates to audio.js setMute()
  document.getElementById('mute-btn').addEventListener('click', function () {
    const isMuted = this.getAttribute('aria-pressed') === 'true';
    setMute(!isMuted);
    this.textContent = isMuted ? '🔊 Mute' : '🔇 Unmute';
    this.setAttribute('aria-pressed', String(!isMuted));
    this.setAttribute('aria-label', isMuted ? 'Mute audio' : 'Unmute audio');
  });

  // Pointermove on textarea — pointerNearInput bridge (task 4.5 / 7.2)
  const textarea = document.getElementById('log-input');
  if (textarea) {
    textarea.addEventListener('pointermove', pointerNearInput);
  }
});
