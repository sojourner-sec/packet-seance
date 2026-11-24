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


// --- AUDIO ---

// (Implemented in task 5.x)


// --- STATE MACHINE ---

// (Implemented in task 4.x)


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
});
