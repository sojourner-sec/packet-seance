// tests/tests-detectors.js — Properties 5–8: detector invariants
// Validates: Requirements 4.1, 4.5, 4.9, 4.6
// Depends on: fast-check (window.fc), detectors.js globals
//   (THRESHOLDS, detectPortScan, detectArpSpoofing,
//    detectCleartextCredentials, detectPingSweep,
//    detectSuspiciousDns, runDetectors)

// ─── Minimal DecodedPacket builders ──────────────────────────────────────────
// Build plain objects matching the shape returned by decodePacket(),
// without going through raw pcap parsing.

function _d_tcpSynPacket(srcIp, dstIp, srcPort, dstPort) {
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

function _d_arpReplyPacket(senderIp, senderMac) {
  return {
    ts: 0, protocol: 'arp',
    eth: null, ip: null, tcp: null, udp: null, dns: null, icmp: null,
    arp: { op: 2, senderIp: senderIp, senderMac: senderMac,
           targetIp: '0.0.0.0', targetMac: '00:00:00:00:00:00' },
    raw: new Uint8Array(0)
  };
}

function _d_httpBasicPacket(srcIp, dstIp, credential) {
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

function _d_icmpEchoPacket(srcIp, dstIp) {
  return {
    ts: 0, protocol: 'icmp',
    eth: null, arp: null, dns: null, tcp: null, udp: null,
    ip:   { src: srcIp, dst: dstIp, protocol: 1, ttl: 64 },
    icmp: { type: 8, code: 0 },
    raw: new Uint8Array(0)
  };
}

function _d_dnsPacket(srcIp, dstIp, name, rcode) {
  return {
    ts: 0, protocol: 'dns',
    eth: null, arp: null, tcp: null, icmp: null,
    ip:  { src: srcIp, dst: dstIp, protocol: 17, ttl: 64 },
    udp: { srcPort: 1234, dstPort: 53, payload: new Uint8Array(0) },
    dns: { name: name || '', qtype: 1, rcode: rcode || 0 },
    raw: new Uint8Array(0)
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

window.detectorTests = [

  // Property 5: Port scan detector respects threshold
  // Validates: Requirements 4.1
  {
    name: 'Property 5: detectPortScan fires iff distinct ports >= portScanMinPorts',
    run: function () {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 30 }),
          function (n) {
            var packets = [];
            for (var port = 1; port <= n; port++) {
              packets.push(_d_tcpSynPacket('10.0.0.1', '10.0.0.2', 40000 + port, port));
            }
            var result     = detectPortScan(packets);
            var shouldFire = n >= THRESHOLDS.portScanMinPorts;

            if (shouldFire && result === null) {
              throw new Error('Expected non-null finding for n=' + n + ' ports');
            }
            if (!shouldFire && result !== null) {
              throw new Error('Expected null for n=' + n + ' ports (below threshold ' +
                              THRESHOLDS.portScanMinPorts + ')');
            }
          }
        )
      );
    }
  },

  // Property 6: ARP spoof detector respects threshold
  // Validates: Requirements 4.5
  {
    name: 'Property 6: detectArpSpoofing fires iff distinct MACs >= arpSpoofMinMacs',
    run: function () {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 5 }),
          function (m) {
            var spoofedIp = '192.168.1.100';
            var packets   = [];
            for (var i = 0; i < m; i++) {
              var hex = i < 16 ? '0' + i.toString(16) : i.toString(16);
              var mac = 'de:ad:be:ef:00:' + hex;
              packets.push(_d_arpReplyPacket(spoofedIp, mac));
            }
            var result     = detectArpSpoofing(packets);
            var shouldFire = m >= THRESHOLDS.arpSpoofMinMacs;

            if (shouldFire && result === null) {
              throw new Error('Expected non-null finding for m=' + m + ' MACs');
            }
            if (!shouldFire && result !== null) {
              throw new Error('Expected null for m=' + m + ' MACs (below threshold ' +
                              THRESHOLDS.arpSpoofMinMacs + ')');
            }
          }
        )
      );
    }
  },

  // Property 7: Credentials are always masked
  // Validates: Requirements 4.9
  {
    name: 'Property 7: HTTP Basic credential longer than 4 chars is never verbatim in evidence',
    run: function () {
      fc.assert(
        fc.property(
          // Generate printable ASCII strings of length 5..40 (longer than the visible prefix)
          fc.string({ minLength: 5, maxLength: 40 }),
          function (cred) {
            // Skip strings that contain whitespace — the HTTP Basic header
            // pattern is \S+ so the regex stops at the first space.
            if (/\s/.test(cred)) return;

            var packets = [_d_httpBasicPacket('192.168.1.5', '93.184.216.34', cred)];
            var finding = detectCleartextCredentials(packets);

            if (finding === null) {
              throw new Error('Expected a finding for credential: ' + cred);
            }
            // The full credential must NOT appear verbatim in evidence.
            if (finding.evidence.indexOf(cred) !== -1) {
              throw new Error('Full credential "' + cred + '" found unmasked in evidence: ' +
                              finding.evidence);
            }
            // The mask marker must be present.
            if (finding.evidence.indexOf('****') === -1) {
              throw new Error('Expected **** in evidence, got: ' + finding.evidence);
            }
          }
        )
      );
    }
  },

  // Property 8: Finding shape is complete
  // Validates: Requirements 4.6
  {
    name: 'Property 8 (detectPortScan): finding has all required fields',
    run: function () {
      var packets = [];
      for (var p = 1; p <= THRESHOLDS.portScanMinPorts; p++) {
        packets.push(_d_tcpSynPacket('10.0.0.1', '10.0.0.2', 40000 + p, p));
      }
      var finding = detectPortScan(packets);
      if (!finding) throw new Error('detectPortScan returned null');
      _assertFindingShape(finding, 'detectPortScan');
    }
  },

  {
    name: 'Property 8 (detectPingSweep): finding has all required fields',
    run: function () {
      var packets = [];
      for (var h = 1; h <= THRESHOLDS.pingSweepMinHosts; h++) {
        packets.push(_d_icmpEchoPacket('10.0.0.1', '192.168.1.' + h));
      }
      var finding = detectPingSweep(packets);
      if (!finding) throw new Error('detectPingSweep returned null');
      _assertFindingShape(finding, 'detectPingSweep');
    }
  },

  {
    name: 'Property 8 (detectSuspiciousDns): finding has all required fields',
    run: function () {
      // Name > dnsLongNameLength chars guarantees the long-name check fires.
      var longName = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com';
      var packets  = [_d_dnsPacket('192.168.1.5', '8.8.8.8', longName, 0)];
      var finding  = detectSuspiciousDns(packets);
      if (!finding) throw new Error('detectSuspiciousDns returned null');
      _assertFindingShape(finding, 'detectSuspiciousDns');
    }
  },

  {
    name: 'Property 8 (detectCleartextCredentials): finding has all required fields',
    run: function () {
      var packets = [_d_httpBasicPacket('192.168.1.5', '93.184.216.34', 'dXNlcjpwYXNz')];
      var finding = detectCleartextCredentials(packets);
      if (!finding) throw new Error('detectCleartextCredentials returned null');
      _assertFindingShape(finding, 'detectCleartextCredentials');
    }
  },

  {
    name: 'Property 8 (detectArpSpoofing): finding has all required fields',
    run: function () {
      var ip      = '192.168.1.100';
      var packets = [
        _d_arpReplyPacket(ip, 'de:ad:be:ef:00:01'),
        _d_arpReplyPacket(ip, 'de:ad:be:ef:00:02'),
      ];
      var finding = detectArpSpoofing(packets);
      if (!finding) throw new Error('detectArpSpoofing returned null');
      _assertFindingShape(finding, 'detectArpSpoofing');
    }
  },

];

// ─── Helper: assert the finding has all required non-empty fields ─────────────

function _assertFindingShape(finding, label) {
  if (typeof finding.type !== 'string' || finding.type.length === 0) {
    throw new Error(label + ': finding.type is not a non-empty string');
  }
  if (typeof finding.severity !== 'string' || finding.severity.length === 0) {
    throw new Error(label + ': finding.severity is not a non-empty string');
  }
  if (!Array.isArray(finding.hosts) || finding.hosts.length === 0) {
    throw new Error(label + ': finding.hosts is not a non-empty array');
  }
  if (typeof finding.evidence !== 'string' || finding.evidence.length === 0) {
    throw new Error(label + ': finding.evidence is not a non-empty string');
  }
  if (typeof finding.packetCount !== 'number' || finding.packetCount <= 0) {
    throw new Error(label + ': finding.packetCount is not a positive number, got: ' +
                    finding.packetCount);
  }
}
