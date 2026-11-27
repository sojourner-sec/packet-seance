// tests/detectors.test.js — property-based tests for detector functions
// Validates: Feature: seance-spirit-board, Properties 5–8
// Depends on: fast-check (fc global), detectors.js globals

// ─── Minimal DecodedPacket builders ──────────────────────────────────────────
// These build plain JS objects that match the shape returned by decodePacket(),
// without going through raw pcap parsing.

function _tcpSynPacket(srcIp, dstIp, srcPort, dstPort) {
  return {
    ts: 0, protocol: 'tcp',
    eth: null, arp: null, dns: null, icmp: null, udp: null,
    ip:  { src: srcIp, dst: dstIp, protocol: 6, ttl: 64 },
    tcp: {
      srcPort: srcPort, dstPort: dstPort,
      flags: { SYN: true, ACK: false, FIN: false, RST: false },
      payload: new Uint8Array(0)
    },
    raw: new Uint8Array(0)
  };
}

function _tcpSynAckPacket(srcIp, dstIp, srcPort, dstPort) {
  return {
    ts: 0, protocol: 'tcp',
    eth: null, arp: null, dns: null, icmp: null, udp: null,
    ip:  { src: srcIp, dst: dstIp, protocol: 6, ttl: 64 },
    tcp: {
      srcPort: srcPort, dstPort: dstPort,
      flags: { SYN: true, ACK: true, FIN: false, RST: false },
      payload: new Uint8Array(0)
    },
    raw: new Uint8Array(0)
  };
}

function _icmpEchoPacket(srcIp, dstIp) {
  return {
    ts: 0, protocol: 'icmp',
    eth: null, arp: null, dns: null, tcp: null, udp: null,
    ip:   { src: srcIp, dst: dstIp, protocol: 1, ttl: 64 },
    icmp: { type: 8, code: 0 },
    raw: new Uint8Array(0)
  };
}

function _arpReplyPacket(senderIp, senderMac) {
  return {
    ts: 0, protocol: 'arp',
    eth: null, ip: null, tcp: null, udp: null, dns: null, icmp: null,
    arp: { op: 2, senderIp: senderIp, senderMac: senderMac,
           targetIp: '0.0.0.0', targetMac: '00:00:00:00:00:00' },
    raw: new Uint8Array(0)
  };
}

function _dnsPacket(srcIp, dstIp, name, rcode) {
  return {
    ts: 0, protocol: 'dns',
    eth: null, arp: null, tcp: null, icmp: null,
    ip:  { src: srcIp, dst: dstIp, protocol: 17, ttl: 64 },
    udp: { srcPort: 1234, dstPort: 53, payload: new Uint8Array(0) },
    dns: { name: name, qtype: 1, rcode: rcode || 0 },
    raw: new Uint8Array(0)
  };
}

function _httpBasicPacket(srcIp, dstIp, credential) {
  var text    = 'GET /admin HTTP/1.1\r\nAuthorization: Basic ' + credential + '\r\n\r\n';
  var payload = new TextEncoder().encode(text);
  return {
    ts: 0, protocol: 'tcp',
    eth: null, arp: null, dns: null, icmp: null, udp: null,
    ip:  { src: srcIp, dst: dstIp, protocol: 6, ttl: 64 },
    tcp: {
      srcPort: 54321, dstPort: 80,
      flags: { SYN: false, ACK: true, FIN: false, RST: false },
      payload: payload
    },
    raw: new Uint8Array(0)
  };
}

// ─── Property 5: Port scan detector respects threshold ───────────────────────
// Tag: Feature: seance-spirit-board, Property 5: Port scan detector respects threshold

window.runTest('Property 5: detectPortScan respects portScanMinPorts threshold', function () {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 30 }),
      function (n) {
        var packets = [];
        for (var port = 1; port <= n; port++) {
          packets.push(_tcpSynPacket('10.0.0.1', '10.0.0.2', 40000 + port, port));
        }
        var result = detectPortScan(packets);
        var shouldFire = n >= THRESHOLDS.portScanMinPorts;
        if (shouldFire && result === null) {
          throw new Error('Expected non-null finding for n=' + n + ' ports');
        }
        if (!shouldFire && result !== null) {
          throw new Error('Expected null finding for n=' + n + ' ports (below threshold)');
        }
      }
    )
  );
});

// ─── Property 6: ARP spoof detector respects threshold ───────────────────────
// Tag: Feature: seance-spirit-board, Property 6: ARP spoof detector respects threshold

window.runTest('Property 6: detectArpSpoofing respects arpSpoofMinMacs threshold', function () {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 5 }),
      function (m) {
        var packets = [];
        var spoofedIp = '192.168.1.100';
        for (var i = 0; i < m; i++) {
          // Each packet has a distinct senderMac
          var mac = 'de:ad:be:ef:00:' + (i < 16 ? '0' : '') + i.toString(16);
          packets.push(_arpReplyPacket(spoofedIp, mac));
        }
        var result    = detectArpSpoofing(packets);
        var shouldFire = m >= THRESHOLDS.arpSpoofMinMacs;
        if (shouldFire && result === null) {
          throw new Error('Expected non-null finding for m=' + m + ' MACs');
        }
        if (!shouldFire && result !== null) {
          throw new Error('Expected null finding for m=' + m + ' MACs (below threshold)');
        }
      }
    )
  );
});

// ─── Property 7: Credentials are always masked ───────────────────────────────
// Tag: Feature: seance-spirit-board, Property 7: Credentials are always masked

var credentialSamples = ['ab', 'abcd', 'abcdefgh', 'dXNlcjpwYXNz', 'YWRtaW46c2VjcmV0MTIz'];

credentialSamples.forEach(function (cred) {
  window.runTest('Property 7: credential "' + cred + '" is masked in evidence', function () {
    var packets = [_httpBasicPacket('192.168.1.5', '93.184.216.34', cred)];
    var finding = detectCleartextCredentials(packets);

    if (finding === null) {
      throw new Error('Expected a finding for credential: ' + cred);
    }
    // The full credential must NOT appear verbatim in the evidence string.
    if (cred.length > 4 && finding.evidence.indexOf(cred) !== -1) {
      throw new Error('Full credential found in evidence (not masked): ' + finding.evidence);
    }
    // The mask marker **** must appear.
    if (finding.evidence.indexOf('****') === -1) {
      throw new Error('Expected **** mask in evidence, got: ' + finding.evidence);
    }
  });
});

// ─── Property 8: Finding shape is complete ───────────────────────────────────
// Tag: Feature: seance-spirit-board, Property 8: Finding shape is complete

// Build minimal packet sets guaranteed to trigger each detector.
var fixturePortScan = (function () {
  var pkts = [];
  for (var p = 1; p <= THRESHOLDS.portScanMinPorts; p++) {
    pkts.push(_tcpSynPacket('10.0.0.1', '10.0.0.2', 40000 + p, p));
  }
  return pkts;
}());

var fixturePingSweep = (function () {
  var pkts = [];
  for (var h = 1; h <= THRESHOLDS.pingSweepMinHosts; h++) {
    pkts.push(_icmpEchoPacket('10.0.0.1', '192.168.1.' + h));
  }
  return pkts;
}());

var fixtureSuspiciousDns = (function () {
  // Name > 40 chars so the long-name check fires immediately.
  var longName = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com';
  return [_dnsPacket('192.168.1.5', '8.8.8.8', longName, 0)];
}());

var fixtureCleartext = (function () {
  return [_httpBasicPacket('192.168.1.5', '93.184.216.34', 'dXNlcjpwYXNz')];
}());

var fixtureArpSpoof = (function () {
  var ip = '192.168.1.100';
  return [
    _arpReplyPacket(ip, 'de:ad:be:ef:00:01'),
    _arpReplyPacket(ip, 'de:ad:be:ef:00:02'),
  ];
}());

var fixtureEntries = [
  { label: 'detectPortScan',             fn: detectPortScan,             packets: fixturePortScan },
  { label: 'detectPingSweep',            fn: detectPingSweep,            packets: fixturePingSweep },
  { label: 'detectSuspiciousDns',        fn: detectSuspiciousDns,        packets: fixtureSuspiciousDns },
  { label: 'detectCleartextCredentials', fn: detectCleartextCredentials, packets: fixtureCleartext },
  { label: 'detectArpSpoofing',          fn: detectArpSpoofing,          packets: fixtureArpSpoof },
];

fixtureEntries.forEach(function (entry) {
  window.runTest('Property 8: ' + entry.label + ' returns a complete finding shape', function () {
    var finding = entry.fn(entry.packets);

    if (finding === null) {
      throw new Error(entry.label + ' returned null — expected a finding');
    }
    if (typeof finding.type !== 'string' || finding.type.length === 0) {
      throw new Error('finding.type is not a non-empty string');
    }
    if (typeof finding.severity !== 'string' || finding.severity.length === 0) {
      throw new Error('finding.severity is not a non-empty string');
    }
    if (!Array.isArray(finding.hosts) || finding.hosts.length === 0) {
      throw new Error('finding.hosts is not a non-empty array');
    }
    if (typeof finding.evidence !== 'string' || finding.evidence.length === 0) {
      throw new Error('finding.evidence is not a non-empty string');
    }
    if (typeof finding.packetCount !== 'number' || finding.packetCount <= 0) {
      throw new Error('finding.packetCount is not a positive number, got: ' + finding.packetCount);
    }
  });
});
