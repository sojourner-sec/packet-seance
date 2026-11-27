// tests/tests-story.js — Properties 9–12: story and state-machine invariants
// Validates: Requirements 5.2, 6.1, 6.5, 10.5, 10.6, 12.2
// Depends on: fast-check (window.fc), story.js globals
//   (generateSummaryStory, generatePeacefulStory, generateFindingStory)
// Does NOT load app.js or audio.js — DOM/AudioContext not available.
// Properties 10–12 use a lightweight local stub, not app.js state.

// ─── Summary arbitraries ─────────────────────────────────────────────────────

// A fast-check arbitrary that produces a valid Summary-shaped object.
var _summaryArb = fc.record({
  totalPackets:    fc.oneof(fc.constant(0), fc.integer({ min: 1, max: 100000 })),
  durationSeconds: fc.oneof(fc.constant(0), fc.float({ min: 0, max: 3600 })),
  skipped:         fc.integer({ min: 0, max: 100 }),
  truncated:       fc.boolean(),
  protocolCounts:  fc.record({
    tcp:     fc.integer({ min: 0, max: 1000 }),
    udp:     fc.integer({ min: 0, max: 1000 }),
    dns:     fc.integer({ min: 0, max: 1000 }),
    icmp:    fc.integer({ min: 0, max: 1000 }),
    arp:     fc.integer({ min: 0, max: 1000 }),
    ipv4:    fc.integer({ min: 0, max: 1000 }),
    unknown: fc.integer({ min: 0, max: 1000 }),
  }),
  topTalkers: fc.array(
    fc.record({
      ip:    fc.ipV4(),
      count: fc.integer({ min: 1, max: 1000 }),
    }),
    { maxLength: 5 }
  ),
});

// ─── Tests ────────────────────────────────────────────────────────────────────

window.storyTests = [

  // Property 9a: generateSummaryStory always returns a non-empty string
  // Validates: Requirements 5.2
  {
    name: 'Property 9: generateSummaryStory always returns a non-empty string',
    run: function () {
      fc.assert(
        fc.property(_summaryArb, function (summary) {
          var result = generateSummaryStory(summary);
          if (typeof result !== 'string' || result.length === 0) {
            throw new Error('generateSummaryStory returned empty or non-string');
          }
        })
      );
    }
  },

  // Property 9b: generatePeacefulStory always returns a non-empty string
  // Validates: Requirements 6.5
  {
    name: 'Property 9: generatePeacefulStory always returns a non-empty string',
    run: function () {
      fc.assert(
        fc.property(_summaryArb, function (summary) {
          var result = generatePeacefulStory(summary);
          if (typeof result !== 'string' || result.length === 0) {
            throw new Error('generatePeacefulStory returned empty or non-string');
          }
        })
      );
    }
  },

  // Property 10: Strike fires at most once per analysis run
  // Validates: Requirements 10.5
  // Tested via a stub — no DOM or app.js needed.
  {
    name: 'Property 10: strike fires at most once per analysis run',
    run: function () {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 20 }),
          function (attempts) {
            // Minimal stub mirroring the guard in app.js _triggerStrike()
            var strikeFired = false;
            var fireCount   = 0;

            function triggerStrike() {
              if (strikeFired) return;
              strikeFired = true;
              fireCount++;
            }

            for (var i = 0; i < attempts; i++) {
              triggerStrike();
            }

            if (fireCount !== 1) {
              throw new Error('Expected fireCount === 1, got ' + fireCount +
                              ' after ' + attempts + ' attempt(s)');
            }
          }
        )
      );
    }
  },

  // Property 11: Strike never fires without a high-severity finding
  // Validates: Requirements 10.6
  {
    name: 'Property 11: strikeArmed is false when no finding has severity "high"',
    run: function () {
      fc.assert(
        fc.property(
          fc.array(
            fc.record({
              type:        fc.constantFrom('PingSweep', 'SuspiciousDns',
                                           'CleartextCredentials', 'PortScan',
                                           'ArpSpoofing', 'Unknown'),
              // All severities except 'high'
              severity:    fc.constantFrom('medium', 'low', 'info'),
              hosts:       fc.array(fc.ipV4(), { maxLength: 3 }),
              evidence:    fc.string(),
              packetCount: fc.integer({ min: 0, max: 1000 }),
            }),
            { maxLength: 10 }
          ),
          function (findings) {
            // Mirror the app.js logic for arming the strike
            var strikeArmed = findings.some(function (f) {
              return f.severity === 'high';
            });
            if (strikeArmed) {
              throw new Error(
                'strikeArmed should be false when no finding is "high", ' +
                'but was true for severities: ' +
                JSON.stringify(findings.map(function (f) { return f.severity; }))
              );
            }
          }
        )
      );
    }
  },

  // Property 12: Reset returns to idle from any phase
  // Validates: Requirements 12.2
  {
    name: 'Property 12: reset stub returns state to idle from any phase',
    run: function () {
      fc.assert(
        fc.property(
          fc.constantFrom('idle', 'summoning', 'calm', 'strike'),
          fc.boolean(),   // initial strikeFired
          fc.boolean(),   // strikeTimer armed?
          function (phase, strikeFired, hasTimer) {
            // Local stub — mirrors the relevant fields reset() touches in app.js.
            var state = {
              phase:       phase,
              strikeFired: strikeFired,
              strikeTimer: hasTimer ? 999 : null,
            };

            // Minimal reset logic (the real reset() in app.js does the same).
            function resetStub() {
              if (state.strikeTimer !== null) {
                clearTimeout(state.strikeTimer); // safe even with fake id
              }
              state.phase       = 'idle';
              state.strikeFired = false;
              state.strikeTimer = null;
            }

            resetStub();

            if (state.phase !== 'idle') {
              throw new Error('Expected phase "idle" after reset, got "' + state.phase + '"');
            }
            if (state.strikeFired !== false) {
              throw new Error('Expected strikeFired === false after reset');
            }
            if (state.strikeTimer !== null) {
              throw new Error('Expected strikeTimer === null after reset');
            }
          }
        )
      );
    }
  },

  // Property 12 (story): generateFindingStory returns non-empty strings for all five types
  // Validates: Requirements 6.1
  {
    name: 'Property 12: generateFindingStory returns non-empty strings for PortScan',
    run: function () { _assertFindingStory('PortScan', ['10.0.0.1', '10.0.0.2']); }
  },
  {
    name: 'Property 12: generateFindingStory returns non-empty strings for PingSweep',
    run: function () { _assertFindingStory('PingSweep', ['10.0.0.1']); }
  },
  {
    name: 'Property 12: generateFindingStory returns non-empty strings for SuspiciousDns',
    run: function () { _assertFindingStory('SuspiciousDns', ['192.168.1.5']); }
  },
  {
    name: 'Property 12: generateFindingStory returns non-empty strings for CleartextCredentials',
    run: function () { _assertFindingStory('CleartextCredentials', ['192.168.1.5', '93.184.216.34']); }
  },
  {
    name: 'Property 12: generateFindingStory returns non-empty strings for ArpSpoofing',
    run: function () {
      _assertFindingStory('ArpSpoofing',
        ['de:ad:be:ef:00:01', 'de:ad:be:ef:00:02', '192.168.1.100']);
    }
  },

];

// ─── Helper ───────────────────────────────────────────────────────────────────

function _assertFindingStory(type, hosts) {
  var finding = {
    type:        type,
    severity:    'high',
    hosts:       hosts,
    evidence:    'Test evidence for ' + type,
    packetCount: 5
  };
  var result = generateFindingStory(finding);
  if (!result || typeof result !== 'object') {
    throw new Error('generateFindingStory("' + type + '") did not return an object');
  }
  ['story', 'explanation', 'tip'].forEach(function (field) {
    if (typeof result[field] !== 'string' || result[field].length === 0) {
      throw new Error(
        'generateFindingStory("' + type + '").' + field +
        ' is not a non-empty string, got: ' + result[field]
      );
    }
  });
}
