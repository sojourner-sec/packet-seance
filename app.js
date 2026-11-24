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

// (Implemented in task 2.x)


// --- AUDIO ---

// (Implemented in task 5.x)


// --- STATE MACHINE ---

// (Implemented in task 4.x)


// --- UI ---

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
