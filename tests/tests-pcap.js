// tests/tests-pcap.js — Properties 1–4: parsePcap invariants
// Validates: Requirements 3.1, 1.4, 3.3, 3.5
// Depends on: fast-check (window.fc), pcap.js globals (parsePcap)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Write a 32-bit little-endian uint into a DataView.
function _p1_setUint32LE(dv, offset, value) {
  dv.setUint32(offset, value, true);
}

// Write a 32-bit big-endian uint into a DataView.
function _p1_setUint32BE(dv, offset, value) {
  dv.setUint32(offset, value, false);
}

// Build a minimal valid 24-byte pcap header buffer (no packets) for the given magic.
function _p1_buildMinimalPcap(magic) {
  var isBE = (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1);
  var buf = new ArrayBuffer(24);
  var dv  = new DataView(buf);

  if (isBE) {
    _p1_setUint32BE(dv, 0,  magic);
    dv.setUint16(4,  2, false);
    dv.setUint16(6,  4, false);
    dv.setInt32 (8,  0, false);
    _p1_setUint32BE(dv, 12, 0);
    _p1_setUint32BE(dv, 16, 65535);
    _p1_setUint32BE(dv, 20, 1); // Ethernet
  } else {
    _p1_setUint32LE(dv, 0,  magic);
    dv.setUint16(4,  2, true);
    dv.setUint16(6,  4, true);
    dv.setInt32 (8,  0, true);
    _p1_setUint32LE(dv, 12, 0);
    _p1_setUint32LE(dv, 16, 65535);
    _p1_setUint32LE(dv, 20, 1);
  }

  return buf;
}

// Build a pcap with `count` zero-payload packet records (LE micro magic).
function _p1_buildPcapWithPackets(count) {
  var buf = new ArrayBuffer(24 + count * 16);
  var dv  = new DataView(buf);

  // File header
  _p1_setUint32LE(dv, 0,  0xa1b2c3d4);
  dv.setUint16(4,  2, true);
  dv.setUint16(6,  4, true);
  dv.setInt32 (8,  0, true);
  _p1_setUint32LE(dv, 12, 0);
  _p1_setUint32LE(dv, 16, 65535);
  _p1_setUint32LE(dv, 20, 1);

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

// ─── Tests ────────────────────────────────────────────────────────────────────

window.pcapTests = [

  // Property 1: Parser handles all supported magic numbers
  // Validates: Requirements 3.1
  {
    name: 'Property 1 (LE micro 0xa1b2c3d4): parsePcap returns packets array',
    run: function () {
      var buf    = _p1_buildMinimalPcap(0xa1b2c3d4);
      var result = parsePcap(buf);
      if (!Array.isArray(result.packets)) throw new Error('packets is not an array');
      if (typeof result.skipped !== 'number') throw new Error('skipped is not a number');
      if (typeof result.truncated !== 'boolean') throw new Error('truncated is not a boolean');
    }
  },

  {
    name: 'Property 1 (BE micro 0xd4c3b2a1): parsePcap returns packets array',
    run: function () {
      var buf    = _p1_buildMinimalPcap(0xd4c3b2a1);
      var result = parsePcap(buf);
      if (!Array.isArray(result.packets)) throw new Error('packets is not an array');
    }
  },

  {
    name: 'Property 1 (LE nano 0xa1b23c4d): parsePcap returns packets array',
    run: function () {
      var buf    = _p1_buildMinimalPcap(0xa1b23c4d);
      var result = parsePcap(buf);
      if (!Array.isArray(result.packets)) throw new Error('packets is not an array');
    }
  },

  {
    name: 'Property 1 (BE nano 0x4d3cb2a1): parsePcap returns packets array',
    run: function () {
      var buf    = _p1_buildMinimalPcap(0x4d3cb2a1);
      var result = parsePcap(buf);
      if (!Array.isArray(result.packets)) throw new Error('packets is not an array');
    }
  },

  // Property 2: Parser rejects pcapng
  // Validates: Requirements 1.4
  {
    name: 'Property 2: parsePcap throws { type: "PCAPNG" } for pcapng magic',
    run: function () {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 20, maxLength: 20 }),
          function (padding) {
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
    }
  },

  // Property 3: Malformed packets are skipped safely
  // Validates: Requirements 3.3
  {
    name: 'Property 3: malformed inclLen past buffer is skipped, no throw',
    run: function () {
      // Build a pcap header + one record where inclLen overflows the buffer.
      var buf = new ArrayBuffer(24 + 16); // header + 16-byte record header only, no payload
      var dv  = new DataView(buf);

      _p1_setUint32LE(dv, 0,  0xa1b2c3d4);
      dv.setUint16(4,  2, true);
      dv.setUint16(6,  4, true);
      dv.setInt32 (8,  0, true);
      _p1_setUint32LE(dv, 12, 0);
      _p1_setUint32LE(dv, 16, 65535);
      _p1_setUint32LE(dv, 20, 1);

      // inclLen = 9999 — far beyond the 0 actual payload bytes available
      dv.setUint32(24,  1000000, true);
      dv.setUint32(28,  0,       true);
      dv.setUint32(32,  9999,    true);
      dv.setUint32(36,  9999,    true);

      var result = parsePcap(buf); // must not throw
      if (result.skipped < 1) {
        throw new Error('Expected skipped >= 1, got ' + result.skipped);
      }
    }
  },

  // Property 4: Parser truncates at 50,000 packets
  // Validates: Requirements 3.5
  {
    name: 'Property 4: parsePcap returns exactly 50,000 packets and truncated=true for 50,001 input',
    run: function () {
      var buf    = _p1_buildPcapWithPackets(50001);
      var result = parsePcap(buf);

      if (result.packets.length !== 50000) {
        throw new Error('Expected 50000 packets, got ' + result.packets.length);
      }
      if (result.truncated !== true) {
        throw new Error('Expected truncated === true, got ' + result.truncated);
      }
    }
  },

];
