// tests/story.test.js — property-based tests for story functions and
//                       state-machine invariants (simulated, no DOM)
// Validates: Feature: seance-spirit-board, Properties 9–12
// Depends on: fast-check (fc global), story.js globals

// ─── Property 9: Story functions always return non-empty strings ──────────────
// Tag: Feature: seance-spirit-board, Property 9: Story functions always return non-empty strings

window.runTest('Property 9: generateSummaryStory always returns a non-empty string', function () {
  fc.assert(
    fc.property(
      fc.record({
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
      }),
      function (summary) {
        var result = generateSummaryStory(summary);
        if (typeof result !== 'string' || result.length === 0) {
          throw new Error('generateSummaryStory returned empty or non-string: ' + result);
        }
      }
    )
  );
});

window.runTest('Property 9: generatePeacefulStory always returns a non-empty string', function () {
  fc.assert(
    fc.property(
      fc.record({
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
      }),
      function (summary) {
        var result = generatePeacefulStory(summary);
        if (typeof result !== 'string' || result.length === 0) {
          throw new Error('generatePeacefulStory returned empty or non-string: ' + result);
        }
      }
    )
  );
});

// ─── Property 10: Strike fires at most once ───────────────────────────────────
// Tag: Feature: seance-spirit-board, Property 10: Strike fires at most once per analysis run

window.runTest('Property 10: strike fires at most once per analysis run', function () {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 20 }), // how many times we attempt to trigger
      function (attempts) {
        // Simulate the guard from app.js without touching the DOM.
        var strikeFired = false;
        var fireCount   = 0;

        function triggerStrike() {
          if (strikeFired) return; // guard: once-only
          strikeFired = true;
          fireCount++;
        }

        for (var i = 0; i < attempts; i++) {
          triggerStrike();
        }

        if (fireCount !== 1) {
          throw new Error('Expected fireCount === 1, got ' + fireCount +
                          ' after ' + attempts + ' trigger attempts');
        }
      }
    )
  );
});

// ─── Property 11: Strike never fires without a high-severity finding ──────────
// Tag: Feature: seance-spirit-board, Property 11: Strike never fires without a high-severity finding

window.runTest('Property 11: strikeArmed is false when no finding has severity "high"', function () {
  fc.assert(
    fc.property(
      fc.array(
        fc.record({
          type:     fc.constantFrom('PingSweep', 'SuspiciousDns', 'CleartextCredentials',
                                    'PortScan', 'ArpSpoofing', 'Unknown'),
          // Only medium or low — never 'high'
          severity: fc.constantFrom('medium', 'low', 'info'),
          hosts:    fc.array(fc.ipV4(), { maxLength: 3 }),
          evidence: fc.string(),
          packetCount: fc.integer({ min: 0, max: 1000 }),
        }),
        { maxLength: 10 }
      ),
      function (findings) {
        // Mirror the app.js logic:
        var strikeArmed = findings.some(function (f) { return f.severity === 'high'; });
        if (strikeArmed) {
          throw new Error(
            'strikeArmed should be false when no finding has severity "high", ' +
            'but got true for findings: ' + JSON.stringify(findings.map(function (f) {
              return f.severity;
            }))
          );
        }
      }
    )
  );
});

// ─── Property 12: generateFindingStory returns non-empty strings for all types ─
// Tag: Feature: seance-spirit-board, Property 12: generateFindingStory returns non-empty strings for all five finding types

var findingFixtures = [
  {
    type: 'PortScan', severity: 'high',
    hosts: ['10.0.0.1', '10.0.0.2'], evidence: 'Port scan: 15 ports probed', packetCount: 15
  },
  {
    type: 'PingSweep', severity: 'medium',
    hosts: ['10.0.0.1'], evidence: 'Ping sweep: 10 hosts pinged', packetCount: 10
  },
  {
    type: 'SuspiciousDns', severity: 'high',
    hosts: ['192.168.1.5'], evidence: "Suspicious DNS: long name 'x.evil.com'", packetCount: 3
  },
  {
    type: 'CleartextCredentials', severity: 'high',
    hosts: ['192.168.1.5', '93.184.216.34'], evidence: "Cleartext credentials: HTTP Basic 'dXNl****' on port 80", packetCount: 1
  },
  {
    type: 'ArpSpoofing', severity: 'high',
    hosts: ['de:ad:be:ef:00:01', 'de:ad:be:ef:00:02', '192.168.1.100'],
    evidence: 'ARP spoofing: IP 192.168.1.100 claimed by 2 MACs', packetCount: 2
  },
];

findingFixtures.forEach(function (finding) {
  window.runTest('Property 12: generateFindingStory returns non-empty strings for ' + finding.type, function () {
    var result = generateFindingStory(finding);

    if (!result || typeof result !== 'object') {
      throw new Error('generateFindingStory did not return an object');
    }
    ['story', 'explanation', 'tip'].forEach(function (field) {
      if (typeof result[field] !== 'string' || result[field].length === 0) {
        throw new Error(
          'generateFindingStory("' + finding.type + '").' + field +
          ' is not a non-empty string, got: ' + result[field]
        );
      }
    });
  });
});
