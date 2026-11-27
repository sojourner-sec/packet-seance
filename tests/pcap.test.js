// tests/pcap.test.js — property-based tests for parsePcap
// Validates: Feature: seance-spirit-board, Properties 1–4
// Depends on: fast-check (fc global), pcap.js globals

// ─── helpers ──────────────────────────────────────────────────────────────────

// Write a 32-bit little-endian uint into a DataView.
function _setUint32LE(dv, offset, value) {
  dv.setUint32(offset, value, true);
}

// Write a 32-bit big-endian uint into a DataView.
function _setUint32BE(dv, offset, value) {
  dv.setUint32(offset, value, false);
}

// Build a minimal valid pcap buffer with zero packets using the given magic.
// Ethernet linkType = 1. No packet records.
function _buildMinimalPcap(magic) {
  // For BE magic numbers the header fields must also be written big-endian.
  var isBE = (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1);
  var buf = new ArrayBuffer(24);
  var dv  = new DataView(buf);

  if (isBE) {
    _setUint32BE(dv, 0,  magic);  // magic
    dv.setUint16(4,  2, false);   // version_major
    dv.setUint16(6,  4, false);   // version_minor
    dv.setInt32 (8,  0, false);   // thiszone
    _setUint32BE(dv, 12, 0);      // sigfigs
    _setUint32BE(dv, 16, 65535);  // snaplen
    _setUint32BE(dv, 20, 1);      // linkType = Ethernet
  } else {
    _setUint32LE(dv, 0,  magic);  // magic
    dv.setUint16(4,  2, true);    // version_major
    dv.setUint16(6,  4, true);    // version_minor
    dv.setInt32 (8,  0, true);    // thiszone
    _setUint32LE(dv, 12, 0);      // sigfigs
    _setUint32LE(dv, 16, 65535);  // snaplen
    _setUint32LE(dv, 20, 1);      // linkType = Ethernet
  }

  return buf;
}

// Build a pcap buffer (LE micro magic) with `count` zero-payload packet records.
function _buildPcapWithPackets(count) {
  // 24-byte file header + count × 16-byte packet record (inclLen = 0, no payload)
  var bufSize = 24 + count * 16;
  var buf = new ArrayBuffer(bufSize);
  var dv  = new DataView(buf);

  // File header
  _setUint32LE(dv, 0,  0xa1b2c3d4); // magic LE micro
  dv.setUint16(4,  2, true);
  dv.setUint16(6,  4, true);
  dv.setInt32 (8,  0, true);
  _setUint32LE(dv, 12, 0);
  _setUint32LE(dv, 16, 65535);
  _setUint32LE(dv, 20, 1);          // linkType Ethernet

  var offset = 24;
  for (var i = 0; i < count; i++) {
    dv.setUint32(offset,      1000000 + i, true); // ts_sec
    dv.setUint32(offset + 4,  0,           true); // ts_usec
    dv.setUint32(offset + 8,  0,           true); // incl_len = 0
    dv.setUint32(offset + 12, 0,           true); // orig_len = 0
    offset += 16;
  }

  return buf;
}

// ─── Property 1: Parser handles all supported magic numbers ──────────────────
// Tag: Feature: seance-spirit-board, Property 1: Parser handles all supported magic numbers

var supportedMagics = [
  { label: 'LE micro (0xa1b2c3d4)', magic: 0xa1b2c3d4 },
  { label: 'BE micro (0xd4c3b2a1)', magic: 0xd4c3b2a1 },
  { label: 'LE nano  (0xa1b23c4d)', magic: 0xa1b23c4d },
  { label: 'BE nano  (0x4d3cb2a1)', magic: 0x4d3cb2a1 },
];

supportedMagics.forEach(function (entry) {
  window.runTest('Property 1: parsePcap accepts ' + entry.label, function () {
    var buf    = _buildMinimalPcap(entry.magic);
    var result = parsePcap(buf); // must not throw

    if (typeof result !== 'object' || result === null) {
      throw new Error('parsePcap did not return an object');
    }
    if (!Array.isArray(result.packets)) {
      throw new Error('result.packets is not an array');
    }
    if (typeof result.skipped !== 'number') {
      throw new Error('result.skipped is not a number');
    }
    if (typeof result.truncated !== 'boolean') {
      throw new Error('result.truncated is not a boolean');
    }
    if (typeof result.linkType !== 'number') {
      throw new Error('result.linkType is not a number');
    }
  });
});

// ─── Property 2: Parser rejects pcapng ───────────────────────────────────────
// Tag: Feature: seance-spirit-board, Property 2: Parser rejects pcapng

window.runTest('Property 2: parsePcap throws PCAPNG for pcapng magic', function () {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 20, maxLength: 20 }), // padding to reach 24 bytes total
      function (padding) {
        // First 4 bytes = pcapng magic, rest = arbitrary padding
        var buf = new ArrayBuffer(24);
        var u8  = new Uint8Array(buf);
        u8[0] = 0x0a; u8[1] = 0x0d; u8[2] = 0x0d; u8[3] = 0x0a;
        u8.set(padding, 4);

        var threw = false;
        var errorType = null;
        try {
          parsePcap(buf);
        } catch (e) {
          threw = true;
          errorType = e && e.type;
        }

        if (!threw) throw new Error('parsePcap did not throw for pcapng input');
        if (errorType !== 'PCAPNG') {
          throw new Error('Expected { type: "PCAPNG" }, got type: ' + errorType);
        }
      }
    )
  );
});

// ─── Property 3: Malformed packets are skipped safely ────────────────────────
// Tag: Feature: seance-spirit-board, Property 3: Malformed packets are skipped safely

window.runTest('Property 3: Malformed packet (inclLen past buffer) is skipped safely', function () {
  // Build a valid pcap header + one packet record where inclLen > remaining buffer.
  var buf = new ArrayBuffer(24 + 16); // header + one record header, no payload
  var dv  = new DataView(buf);

  _setUint32LE(dv, 0,  0xa1b2c3d4); // magic
  dv.setUint16(4,  2, true);
  dv.setUint16(6,  4, true);
  dv.setInt32 (8,  0, true);
  _setUint32LE(dv, 12, 0);
  _setUint32LE(dv, 16, 65535);
  _setUint32LE(dv, 20, 1); // Ethernet

  // Packet record: inclLen = 9999 (far past the 0-byte actual payload)
  dv.setUint32(24,  1000000, true); // ts_sec
  dv.setUint32(28,  0,       true); // ts_usec
  dv.setUint32(32,  9999,    true); // incl_len — oversized
  dv.setUint32(36,  9999,    true); // orig_len

  var result = parsePcap(buf); // must NOT throw
  if (result.skipped < 1) {
    throw new Error('Expected skipped >= 1, got ' + result.skipped);
  }
});

// ─── Property 4: Parser truncates at 50,000 packets ─────────────────────────
// Tag: Feature: seance-spirit-board, Property 4: Parser truncates at 50,000 packets

window.runTest('Property 4: parsePcap truncates at 50,000 packets', function () {
  var COUNT = 50001;
  var buf    = _buildPcapWithPackets(COUNT);
  var result = parsePcap(buf);

  if (result.packets.length !== 50000) {
    throw new Error('Expected 50000 packets, got ' + result.packets.length);
  }
  if (result.truncated !== true) {
    throw new Error('Expected truncated === true');
  }
});
