// pcap.js — packet parser (pure functions, no DOM access)
// Tasks: 4.1 parsePcap, 4.3 decodePacket, 4.4 buildSummary

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Format 6 bytes at offset as "aa:bb:cc:dd:ee:ff" (big-endian read). */
function _macToString(view, offset) {
  var parts = [];
  for (var i = 0; i < 6; i++) {
    var byte = view.getUint8(offset + i);
    parts.push(byte < 16 ? '0' + byte.toString(16) : byte.toString(16));
  }
  return parts.join(':');
}

/** Format 4 bytes at offset as "192.168.1.1" (big-endian read). */
function _ipToString(view, offset) {
  return (
    view.getUint8(offset) + '.' +
    view.getUint8(offset + 1) + '.' +
    view.getUint8(offset + 2) + '.' +
    view.getUint8(offset + 3)
  );
}

/**
 * Read a DNS label-encoded name from a DataView starting at offset.
 * Stops if offset goes past maxOffset, or on a null label, or on a pointer
 * (0xC0 compression pointer — not followed; replaced with '<ptr>').
 * Returns { name: string, bytesRead: number }.
 */
function _parseDnsName(view, offset, maxOffset) {
  var labels = [];
  var start = offset;

  while (offset < maxOffset) {
    var len = view.getUint8(offset);

    // Null terminator — end of name
    if (len === 0) {
      offset += 1;
      break;
    }

    // Compression pointer (top two bits = 11) — do not follow; mark and stop
    if ((len & 0xC0) === 0xC0) {
      labels.push('<ptr>');
      offset += 2;
      break;
    }

    offset += 1;
    if (offset + len > maxOffset) break; // would read past buffer

    var chars = [];
    for (var i = 0; i < len; i++) {
      chars.push(String.fromCharCode(view.getUint8(offset + i)));
    }
    labels.push(chars.join(''));
    offset += len;
  }

  return { name: labels.join('.'), bytesRead: offset - start };
}

// ─── DNS decoder ────────────────────────────────────────────────────────────

/**
 * Decode a DNS message from a Uint8Array payload.
 * Returns { name, qtype, rcode } or null on any parse error.
 */
function _decodeDns(payload) {
  try {
    if (payload.length < 12) return null; // need at least the header
    var view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

    // DNS header: txid(2), flags(2), qdcount(2), ancount(2), nscount(2), arcount(2)
    var flags   = view.getUint16(2, false);
    var qdcount = view.getUint16(4, false);
    var rcode   = flags & 0x000F;

    if (qdcount === 0) {
      // No question section — still return rcode (may be a reply)
      return { name: '', qtype: 0, rcode: rcode };
    }

    // Parse the first question
    var maxOffset = payload.byteLength;
    var result = _parseDnsName(view, 12, maxOffset);
    var nameEnd = 12 + result.bytesRead;

    var qtype = 0;
    if (nameEnd + 4 <= maxOffset) {
      qtype = view.getUint16(nameEnd, false);
      // qclass is at nameEnd+2 — not needed for detectors
    }

    return { name: result.name, qtype: qtype, rcode: rcode };
  } catch (e) {
    return null;
  }
}

// ─── decodePacket ────────────────────────────────────────────────────────────

/**
 * Decode one raw packet buffer into a DecodedPacket object.
 *
 * @param {Uint8Array} rawBytes  - raw packet bytes
 * @param {number}     linkType  - pcap link type (1 = Ethernet)
 * @param {number}     tsSeconds - integer seconds part of timestamp
 * @param {number}     tsNanoseconds - sub-second part in nanoseconds
 * @returns {DecodedPacket}
 */
function decodePacket(rawBytes, linkType, tsSeconds, tsNanoseconds) {
  // Build the base result that is always returned (even on error)
  var ts = tsSeconds + (tsNanoseconds / 1e9);

  var base = {
    ts:       ts,
    eth:      null,
    arp:      null,
    ip:       null,
    tcp:      null,
    udp:      null,
    icmp:     null,
    dns:      null,
    raw:      rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(0),
    protocol: 'unknown'
  };

  try {
    // Only Ethernet (link type 1) is fully decoded
    if (linkType !== 1) return base;
    if (rawBytes.length < 14) return base; // too short for Ethernet header

    var view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);

    // ── Ethernet header (14 bytes) ──────────────────────────────────────────
    var ethDst      = _macToString(view, 0);
    var ethSrc      = _macToString(view, 6);
    var etherType   = view.getUint16(12, false); // big-endian

    base.eth = { src: ethSrc, dst: ethDst, etherType: etherType };
    base.protocol = 'ipv4'; // default; overridden below

    // ── ARP (EtherType 0x0806) ──────────────────────────────────────────────
    if (etherType === 0x0806) {
      base.protocol = 'arp';
      // ARP payload starts at byte 14; need at least 28 more bytes
      if (rawBytes.length >= 14 + 28) {
        var aOff = 14;
        // htype(2), ptype(2), hlen(1), plen(1), op(2), senderMac(6), senderIp(4), targetMac(6), targetIp(4)
        var op        = view.getUint16(aOff + 6, false);
        var senderMac = _macToString(view, aOff + 8);
        var senderIp  = _ipToString(view, aOff + 14);
        var targetMac = _macToString(view, aOff + 18);
        var targetIp  = _ipToString(view, aOff + 24);
        base.arp = { op: op, senderIp: senderIp, senderMac: senderMac, targetIp: targetIp, targetMac: targetMac };
      }
      return base;
    }

    // ── IPv4 (EtherType 0x0800) ─────────────────────────────────────────────
    if (etherType !== 0x0800) {
      base.protocol = 'unknown';
      return base;
    }

    // Need at least 20 bytes for IPv4 header after Ethernet
    if (rawBytes.length < 14 + 20) return base;

    var ipOff    = 14;
    var ihlByte  = view.getUint8(ipOff);
    var ihl      = (ihlByte & 0x0F) * 4; // header length in bytes (includes options)
    var ipProto  = view.getUint8(ipOff + 9);
    var ttl      = view.getUint8(ipOff + 8);
    var ipSrc    = _ipToString(view, ipOff + 12);
    var ipDst    = _ipToString(view, ipOff + 16);

    base.ip = { src: ipSrc, dst: ipDst, protocol: ipProto, ttl: ttl };
    base.protocol = 'ipv4';

    var l4Off = ipOff + ihl; // start of transport layer

    // ── ICMP (protocol 1) ───────────────────────────────────────────────────
    if (ipProto === 1) {
      base.protocol = 'icmp';
      if (rawBytes.length >= l4Off + 4) {
        base.icmp = {
          type: view.getUint8(l4Off),
          code: view.getUint8(l4Off + 1)
        };
      }
      return base;
    }

    // ── TCP (protocol 6) ────────────────────────────────────────────────────
    if (ipProto === 6) {
      base.protocol = 'tcp';
      if (rawBytes.length < l4Off + 20) return base; // too short for TCP header

      var tcpSrcPort = view.getUint16(l4Off,     false);
      var tcpDstPort = view.getUint16(l4Off + 2, false);
      var dataOffByte = view.getUint8(l4Off + 12);
      var tcpHeaderLen = ((dataOffByte >> 4) & 0x0F) * 4;
      var flagsByte    = view.getUint8(l4Off + 13);

      var tcpPayloadStart = l4Off + tcpHeaderLen;
      var tcpPayload = rawBytes.slice(tcpPayloadStart);

      base.tcp = {
        srcPort: tcpSrcPort,
        dstPort: tcpDstPort,
        flags: {
          FIN: (flagsByte & 0x01) !== 0,
          SYN: (flagsByte & 0x02) !== 0,
          RST: (flagsByte & 0x04) !== 0,
          ACK: (flagsByte & 0x10) !== 0
        },
        payload: tcpPayload
      };
      return base;
    }

    // ── UDP (protocol 17) ───────────────────────────────────────────────────
    if (ipProto === 17) {
      base.protocol = 'udp';
      if (rawBytes.length < l4Off + 8) return base; // too short for UDP header

      var udpSrcPort = view.getUint16(l4Off,     false);
      var udpDstPort = view.getUint16(l4Off + 2, false);
      var udpPayload = rawBytes.slice(l4Off + 8);

      base.udp = {
        srcPort: udpSrcPort,
        dstPort: udpDstPort,
        payload: udpPayload
      };

      // DNS on port 53
      if (udpSrcPort === 53 || udpDstPort === 53) {
        base.protocol = 'dns';
        base.dns = _decodeDns(udpPayload);
      }

      return base;
    }

    // Other IP protocols — leave protocol as 'ipv4', all transport fields null
    return base;

  } catch (e) {
    // On any unexpected error, return the minimal safe base object
    base.protocol = 'unknown';
    return base;
  }
}

// ─── parsePcap ───────────────────────────────────────────────────────────────

/**
 * Parse a classic pcap ArrayBuffer and return decoded packets.
 *
 * Supported magic numbers:
 *   0xa1b2c3d4 — little-endian, microsecond timestamps
 *   0xd4c3b2a1 — big-endian,    microsecond timestamps
 *   0xa1b23c4d — little-endian, nanosecond timestamps
 *   0x4d3cb2a1 — big-endian,    nanosecond timestamps
 *
 * Throws { type: 'PCAPNG' }  if the file is pcapng.
 * Throws { type: 'INVALID' } if the magic is unrecognised or buffer is too short.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @returns {{ packets: DecodedPacket[], skipped: number, truncated: boolean, linkType: number }}
 */
function parsePcap(arrayBuffer) {
  var MAX_PACKETS = 50000;

  if (arrayBuffer.byteLength < 24) {
    throw { type: 'INVALID' };
  }

  var view = new DataView(arrayBuffer);

  // Check for pcapng magic (0x0a 0x0d 0x0d 0x0a) — byte order independent
  var firstByte = view.getUint8(0);
  var secondByte = view.getUint8(1);
  var thirdByte = view.getUint8(2);
  var fourthByte = view.getUint8(3);
  if (firstByte === 0x0a && secondByte === 0x0d && thirdByte === 0x0d && fourthByte === 0x0a) {
    throw { type: 'PCAPNG' };
  }

  // Read magic (always read as little-endian first to detect byte order)
  var magicLE = view.getUint32(0, true);
  var le, nanoseconds;

  if (magicLE === 0xa1b2c3d4) {
    le = true;  nanoseconds = false;
  } else if (magicLE === 0xa1b23c4d) {
    le = true;  nanoseconds = true;
  } else {
    // Try big-endian
    var magicBE = view.getUint32(0, false);
    if (magicBE === 0xd4c3b2a1) {
      le = false; nanoseconds = false;
    } else if (magicBE === 0x4d3cb2a1) {
      le = false; nanoseconds = true;
    } else {
      throw { type: 'INVALID' };
    }
  }

  // Read file header fields
  // magic(4), version_major(2), version_minor(2), thiszone(4), sigfigs(4), snaplen(4), linkType(4)
  var linkType = view.getUint32(20, le);

  var packets = [];
  var skipped = 0;
  var truncated = false;
  var offset = 24; // first packet record starts right after the 24-byte file header
  var bufferEnd = arrayBuffer.byteLength;

  while (offset < bufferEnd) {
    // Need 16 bytes for the per-packet record header
    if (offset + 16 > bufferEnd) {
      break;
    }

    // Check if we have already reached the packet limit
    if (packets.length >= MAX_PACKETS) {
      // There are more records — flag truncation
      truncated = true;
      break;
    }

    var tsSec  = view.getUint32(offset,     le);
    var tsSub  = view.getUint32(offset + 4, le); // usec or nsec depending on magic
    var inclLen = view.getUint32(offset + 8, le);
    // orig_len at offset+12 is not needed for decoding

    offset += 16;

    // Safety: inclLen must not read past the buffer
    if (offset + inclLen > bufferEnd) {
      skipped++;
      // Try to advance anyway (may point past buffer — loop condition catches it)
      offset += inclLen;
      continue;
    }

    // Extract raw packet bytes
    var rawBytes = new Uint8Array(arrayBuffer, offset, inclLen);

    // Convert sub-second field to nanoseconds for decodePacket
    var tsNanoseconds = nanoseconds ? tsSub : tsSub * 1000;

    packets.push(decodePacket(rawBytes, linkType, tsSec, tsNanoseconds));

    offset += inclLen;
  }

  return {
    packets:   packets,
    skipped:   skipped,
    truncated: truncated,
    linkType:  linkType
  };
}

// ─── buildSummary ────────────────────────────────────────────────────────────

/**
 * Aggregate decoded packets into a surface summary.
 *
 * @param {DecodedPacket[]} packets - output of parsePcap().packets
 * @param {{ skipped?: number, truncated?: boolean }} [meta] - optional values
 *        from parsePcap() return; defaults to { skipped: 0, truncated: false }
 * @returns {Summary}
 */
function buildSummary(packets, meta) {
  var skipped   = (meta && meta.skipped   != null) ? meta.skipped   : 0;
  var truncated = (meta && meta.truncated != null) ? meta.truncated : false;

  // Duration: last ts minus first ts, or 0 if fewer than 2 packets
  var durationSeconds = 0;
  if (packets.length >= 2) {
    durationSeconds = packets[packets.length - 1].ts - packets[0].ts;
  }

  // Protocol counts — initialize all buckets to 0
  var protocolCounts = { arp: 0, ipv4: 0, tcp: 0, udp: 0, icmp: 0, dns: 0, unknown: 0 };
  for (var i = 0; i < packets.length; i++) {
    var proto = packets[i].protocol;
    if (protocolCounts.hasOwnProperty(proto)) {
      protocolCounts[proto]++;
    } else {
      protocolCounts.unknown++;
    }
  }

  // Top talkers: count packets by source IP (only packets that have ip field)
  var ipCounts = {};
  for (var j = 0; j < packets.length; j++) {
    var pkt = packets[j];
    if (pkt.ip && pkt.ip.src) {
      var src = pkt.ip.src;
      ipCounts[src] = (ipCounts[src] || 0) + 1;
    }
  }

  // Sort descending by count and take top 5
  var talkers = Object.keys(ipCounts).map(function(ip) {
    return { ip: ip, count: ipCounts[ip] };
  });
  talkers.sort(function(a, b) { return b.count - a.count; });
  var topTalkers = talkers.slice(0, 5);

  return {
    totalPackets:    packets.length,
    skipped:         skipped,
    truncated:       truncated,
    durationSeconds: durationSeconds,
    protocolCounts:  protocolCounts,
    topTalkers:      topTalkers
  };
}
