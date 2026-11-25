// samples.js — Synthetic pcap capture generators.
// Each function returns an ArrayBuffer containing a valid classic pcap file.
// All packets use Ethernet (linkType 1), little-endian byte order, magic 0xa1b2c3d4.
// No ES module imports — plain globals only.

// ─── pcap builder helpers ────────────────────────────────────────────────────

// Write the 24-byte global pcap file header into dv starting at offset.
function _writePcapFileHeader(dv, offset) {
  dv.setUint32(offset,      0xa1b2c3d4, true); // magic (LE, microseconds)
  dv.setUint16(offset + 4,  2,          true); // version_major
  dv.setUint16(offset + 6,  4,          true); // version_minor
  dv.setInt32 (offset + 8,  0,          true); // thiszone
  dv.setUint32(offset + 12, 0,          true); // sigfigs
  dv.setUint32(offset + 16, 65535,      true); // snaplen
  dv.setUint32(offset + 20, 1,          true); // network = Ethernet
}

// Write the 16-byte per-packet header and copy frame bytes; returns next offset.
function _writePacketRecord(dv, u8, offset, tsSec, tsUsec, frame) {
  dv.setUint32(offset,     tsSec,            true); // ts_sec
  dv.setUint32(offset + 4, tsUsec,           true); // ts_usec
  dv.setUint32(offset + 8, frame.byteLength, true); // incl_len
  dv.setUint32(offset + 12, frame.byteLength, true); // orig_len
  u8.set(frame, offset + 16);
  return offset + 16 + frame.byteLength;
}

// Encode a dotted-decimal IPv4 string into 4 bytes starting at u8[offset].
function _writeIPv4(u8, offset, ip) {
  const parts = ip.split('.').map(Number);
  u8[offset]     = parts[0];
  u8[offset + 1] = parts[1];
  u8[offset + 2] = parts[2];
  u8[offset + 3] = parts[3];
}

// Encode a colon-separated MAC string into 6 bytes starting at u8[offset].
function _writeMAC(u8, offset, mac) {
  const parts = mac.split(':').map(s => parseInt(s, 16));
  for (let i = 0; i < 6; i++) u8[offset + i] = parts[i];
}

// ─── Ethernet frame builders ─────────────────────────────────────────────────

// Build a 42-byte Ethernet + ARP frame.
//   op: 1=request, 2=reply
function _buildArpFrame(srcMac, dstMac, op, senderMac, senderIp, targetMac, targetIp) {
  const frame = new Uint8Array(42); // 14 (Eth) + 28 (ARP)

  // Ethernet header
  _writeMAC(frame, 0, dstMac);             // dst MAC
  _writeMAC(frame, 6, srcMac);             // src MAC
  frame[12] = 0x08; frame[13] = 0x06;      // EtherType ARP

  // ARP payload
  frame[14] = 0x00; frame[15] = 0x01;      // hardware type Ethernet
  frame[16] = 0x08; frame[17] = 0x00;      // protocol type IPv4
  frame[18] = 6;                            // hardware addr length
  frame[19] = 4;                            // protocol addr length
  frame[20] = 0x00; frame[21] = op;         // operation
  _writeMAC(frame, 22, senderMac);         // sender MAC
  _writeIPv4(frame, 28, senderIp);         // sender IP
  _writeMAC(frame, 32, targetMac);         // target MAC (zeros for request)
  _writeIPv4(frame, 38, targetIp);         // target IP

  return frame;
}

// Build a minimal DNS query for 'example.com' as a Uint8Array.
// Returns the DNS message bytes only (no transport headers).
function _buildDnsQueryPayload() {
  // Header: ID=0x0001, Flags=0x0100 (standard query), QDCOUNT=1
  // Question: \x07example\x03com\x00, qtype A (1), qclass IN (1)
  return new Uint8Array([
    0x00, 0x01,  // transaction ID
    0x01, 0x00,  // flags: standard query, recursion desired
    0x00, 0x01,  // QDCOUNT = 1
    0x00, 0x00,  // ANCOUNT = 0
    0x00, 0x00,  // NSCOUNT = 0
    0x00, 0x00,  // ARCOUNT = 0
    // Question section: example.com
    0x07,                                     // length 7
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // 'example'
    0x03,                                     // length 3
    0x63, 0x6f, 0x6d,                          // 'com'
    0x00,                                     // root label
    0x00, 0x01,  // qtype A
    0x00, 0x01,  // qclass IN
  ]);
}

// Build a full Ethernet+IPv4+UDP+DNS frame.
function _buildDnsQueryFrame(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort) {
  const dnsPayload = _buildDnsQueryPayload();
  const udpLen = 8 + dnsPayload.length;    // UDP header + data
  const ipLen  = 20 + udpLen;              // IP header + UDP
  const totalLen = 14 + ipLen;             // Ethernet header + IP

  const frame = new Uint8Array(totalLen);
  const dv    = new DataView(frame.buffer);

  // Ethernet header
  _writeMAC(frame, 0, dstMac);
  _writeMAC(frame, 6, srcMac);
  frame[12] = 0x08; frame[13] = 0x00;     // EtherType IPv4

  // IPv4 header (no options)
  frame[14] = 0x45;                        // version 4, IHL 5
  frame[15] = 0x00;                        // DSCP/ECN
  dv.setUint16(16, ipLen, false);          // total length (big-endian)
  dv.setUint16(18, 0x1234, false);         // identification
  dv.setUint16(20, 0x4000, false);         // flags: DF, frag offset 0
  frame[22] = 64;                          // TTL
  frame[23] = 17;                          // protocol UDP
  dv.setUint16(24, 0, false);              // checksum (0 = not computed)
  _writeIPv4(frame, 26, srcIp);
  _writeIPv4(frame, 30, dstIp);

  // UDP header
  dv.setUint16(34, srcPort, false);
  dv.setUint16(36, dstPort, false);
  dv.setUint16(38, udpLen,  false);        // length
  dv.setUint16(40, 0,       false);        // checksum (0 = not computed)

  // DNS payload
  frame.set(dnsPayload, 42);

  return frame;
}

// Build a full Ethernet+IPv4+TCP frame with a text payload.
// flags: bitmask — 0x002=SYN, 0x010=ACK, 0x001=FIN, 0x004=RST
function _buildTcpFrame(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, flags, payloadText) {
  const payload = new TextEncoder().encode(payloadText);
  const tcpHeaderLen = 20;                 // no options, data offset = 5
  const ipLen  = 20 + tcpHeaderLen + payload.length;
  const totalLen = 14 + ipLen;

  const frame = new Uint8Array(totalLen);
  const dv    = new DataView(frame.buffer);

  // Ethernet header
  _writeMAC(frame, 0, dstMac);
  _writeMAC(frame, 6, srcMac);
  frame[12] = 0x08; frame[13] = 0x00;     // EtherType IPv4

  // IPv4 header
  frame[14] = 0x45;
  frame[15] = 0x00;
  dv.setUint16(16, ipLen, false);
  dv.setUint16(18, 0x5678, false);
  dv.setUint16(20, 0x4000, false);
  frame[22] = 64;
  frame[23] = 6;                           // protocol TCP
  dv.setUint16(24, 0, false);
  _writeIPv4(frame, 26, srcIp);
  _writeIPv4(frame, 30, dstIp);

  // TCP header
  dv.setUint16(34, srcPort, false);
  dv.setUint16(36, dstPort, false);
  dv.setUint32(38, 1000, false);           // seq
  dv.setUint32(42, 2000, false);           // ack
  frame[46] = 0x50;                        // data offset = 5 (no options)
  frame[47] = flags & 0xff;               // flags byte
  dv.setUint16(48, 65535, false);          // window
  dv.setUint16(50, 0, false);              // checksum
  dv.setUint16(52, 0, false);              // urgent pointer

  // TCP payload
  frame.set(payload, 54);

  return frame;
}

// ─── generateQuietHouseCapture ───────────────────────────────────────────────

/**
 * Returns a valid classic pcap ArrayBuffer containing 5 benign packets:
 * ARP request, ARP reply, DNS query, HTTP GET, HTTP 200 OK.
 * None of these packets trigger any detector.
 */
function generateQuietHouseCapture() {
  const MAC_A  = 'aa:bb:cc:11:22:33';  // 192.168.1.1
  const MAC_B  = 'dd:ee:ff:44:55:66';  // 192.168.1.2
  const MAC_Z  = '00:00:00:00:00:00';  // zero MAC for ARP request target
  const BCAST  = 'ff:ff:ff:ff:ff:ff';
  const IP_A   = '192.168.1.1';
  const IP_B   = '192.168.1.2';
  const IP_WEB = '93.184.216.34';      // example.com
  const IP_DNS = '8.8.8.8';

  // Build all five frames
  const frame1 = _buildArpFrame(MAC_A, BCAST, 1, MAC_A, IP_A, MAC_Z, IP_B);
  const frame2 = _buildArpFrame(MAC_B, MAC_A, 2, MAC_B, IP_B, MAC_A, IP_A);
  const frame3 = _buildDnsQueryFrame(MAC_A, MAC_B, IP_A, IP_DNS, 54321, 53);
  // HTTP GET — ACK flag set (0x010), not SYN-only, so port-scan detector ignores it
  const frame4 = _buildTcpFrame(MAC_A, MAC_B, IP_A, IP_WEB, 49152, 80, 0x010,
                                 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  // HTTP 200 response — reverse direction
  const frame5 = _buildTcpFrame(MAC_B, MAC_A, IP_WEB, IP_A, 80, 49152, 0x010,
                                 'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!');

  const frames = [frame1, frame2, frame3, frame4, frame5];
  const totalFrameBytes = frames.reduce((sum, f) => sum + f.byteLength, 0);

  // 24-byte file header + 5 × (16-byte packet header + frame bytes)
  const bufSize = 24 + frames.length * 16 + totalFrameBytes;
  const buf = new ArrayBuffer(bufSize);
  const dv  = new DataView(buf);
  const u8  = new Uint8Array(buf);

  _writePcapFileHeader(dv, 0);

  // Per-packet timestamps: 1_000_000 s through 1_000_004 s, usec 0
  let offset = 24;
  frames.forEach((frame, i) => {
    offset = _writePacketRecord(dv, u8, offset, 1000000 + i, 0, frame);
  });

  return buf;
}

// Build a full Ethernet+IPv4+ICMP echo request frame.
function _buildIcmpEchoFrame(srcMac, dstMac, srcIp, dstIp, icmpId, icmpSeq) {
  const icmpLen  = 8;              // type(1) code(1) checksum(2) id(2) seq(2)
  const ipLen    = 20 + icmpLen;
  const totalLen = 14 + ipLen;

  const frame = new Uint8Array(totalLen);
  const dv    = new DataView(frame.buffer);

  // Ethernet header
  _writeMAC(frame, 0, dstMac);
  _writeMAC(frame, 6, srcMac);
  frame[12] = 0x08; frame[13] = 0x00;  // EtherType IPv4

  // IPv4 header
  frame[14] = 0x45;                     // version 4, IHL 5
  frame[15] = 0x00;                     // DSCP/ECN
  dv.setUint16(16, ipLen,    false);    // total length (big-endian)
  dv.setUint16(18, 0xabcd,   false);   // identification
  dv.setUint16(20, 0x4000,   false);   // flags: DF, frag offset 0
  frame[22] = 64;                       // TTL
  frame[23] = 1;                        // protocol ICMP
  dv.setUint16(24, 0,        false);   // checksum (0 = not computed)
  _writeIPv4(frame, 26, srcIp);
  _writeIPv4(frame, 30, dstIp);

  // ICMP echo request
  frame[34] = 8;                        // type: echo request
  frame[35] = 0;                        // code: 0
  dv.setUint16(36, 0,        false);   // checksum (0 = not computed)
  dv.setUint16(38, icmpId,   false);   // identifier
  dv.setUint16(40, icmpSeq,  false);   // sequence number

  return frame;
}

// ─── generateKnockingVisitorCapture ──────────────────────────────────────────

/**
 * Returns a valid classic pcap ArrayBuffer that triggers PortScan (high) and
 * PingSweep (medium):
 * - 20 TCP SYN packets from 10.0.0.1 to 10.0.0.2 on 20 distinct destination
 *   ports (well above portScanMinPorts = 15, zero completed handshakes).
 * - 12 ICMP echo requests from 10.0.0.1 to 12 distinct /24 hosts
 *   (above pingSweepMinHosts = 10).
 */
function generateKnockingVisitorCapture() {
  const MAC_SCAN = 'aa:11:22:33:44:55';  // scanner
  const MAC_TGT  = 'bb:66:77:88:99:aa';  // scan target
  const MAC_GW   = 'cc:dd:ee:ff:00:11';  // gateway (ICMP destinations route via it)
  const IP_SCAN  = '10.0.0.1';
  const IP_TGT   = '10.0.0.2';

  // 20 TCP SYN frames to 20 distinct destination ports
  const synFrames = [];
  for (let port = 1; port <= 20; port++) {
    // srcPort varies, dstPort is the scan target port, flags = 0x002 (SYN only)
    synFrames.push(_buildTcpFrame(MAC_SCAN, MAC_TGT, IP_SCAN, IP_TGT,
                                  40000 + port, port, 0x002, ''));
  }

  // 12 ICMP echo request frames to 12 distinct destination IPs
  const icmpFrames = [];
  for (let host = 1; host <= 12; host++) {
    const dstIp = `192.168.1.${host}`;
    icmpFrames.push(_buildIcmpEchoFrame(MAC_SCAN, MAC_GW, IP_SCAN, dstIp,
                                        0x0001, host));
  }

  const frames = [...synFrames, ...icmpFrames];
  const totalFrameBytes = frames.reduce((sum, f) => sum + f.byteLength, 0);

  // 24-byte file header + N × (16-byte packet header + frame bytes)
  const bufSize = 24 + frames.length * 16 + totalFrameBytes;
  const buf = new ArrayBuffer(bufSize);
  const dv  = new DataView(buf);
  const u8  = new Uint8Array(buf);

  _writePcapFileHeader(dv, 0);

  let offset = 24;
  frames.forEach((frame, i) => {
    offset = _writePacketRecord(dv, u8, offset, 1000000 + i, 0, frame);
  });

  return buf;
}

// ─── generateWhisperingWireCapture helpers ───────────────────────────────────

// Encode a DNS name (e.g. "sub.evil.com") into wire-format label bytes.
function _encodeDnsName(name) {
  const labels = name.split('.');
  const parts  = [];
  for (const label of labels) {
    const bytes = new TextEncoder().encode(label);
    parts.push(bytes.length);
    for (const b of bytes) parts.push(b);
  }
  parts.push(0x00); // root label
  return new Uint8Array(parts);
}

// Build a DNS message (query or NXDOMAIN reply) for the given name.
//   flags: 0x0100 = standard query; 0x8183 = QR=1, RD=1, RA=1, rcode=3 (NXDOMAIN)
function _buildDnsMessage(name, flags) {
  const qname  = _encodeDnsName(name);
  const msgLen = 12 + qname.length + 4; // header(12) + qname + qtype(2) + qclass(2)
  const msg    = new Uint8Array(msgLen);
  const dv     = new DataView(msg.buffer);

  dv.setUint16(0,  0x0001, false); // transaction ID
  dv.setUint16(2,  flags,  false); // flags
  dv.setUint16(4,  1,      false); // QDCOUNT
  dv.setUint16(6,  0,      false); // ANCOUNT
  dv.setUint16(8,  0,      false); // NSCOUNT
  dv.setUint16(10, 0,      false); // ARCOUNT

  msg.set(qname, 12);
  const afterName = 12 + qname.length;
  dv.setUint16(afterName,     1, false); // qtype A
  dv.setUint16(afterName + 2, 1, false); // qclass IN

  return msg;
}

// Build a full Ethernet+IPv4+UDP frame carrying a DNS payload.
function _buildDnsFrame(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, dnsPayload) {
  const udpLen = 8 + dnsPayload.length;
  const ipLen  = 20 + udpLen;
  const total  = 14 + ipLen;

  const frame = new Uint8Array(total);
  const dv    = new DataView(frame.buffer);

  // Ethernet
  _writeMAC(frame, 0, dstMac);
  _writeMAC(frame, 6, srcMac);
  frame[12] = 0x08; frame[13] = 0x00; // EtherType IPv4

  // IPv4
  frame[14] = 0x45;
  frame[15] = 0x00;
  dv.setUint16(16, ipLen,  false);
  dv.setUint16(18, 0xABCD, false);
  dv.setUint16(20, 0x4000, false); // DF flag
  frame[22] = 64;
  frame[23] = 17;                   // protocol UDP
  dv.setUint16(24, 0,      false); // checksum omitted
  _writeIPv4(frame, 26, srcIp);
  _writeIPv4(frame, 30, dstIp);

  // UDP
  dv.setUint16(34, srcPort, false);
  dv.setUint16(36, dstPort, false);
  dv.setUint16(38, udpLen,  false);
  dv.setUint16(40, 0,       false); // checksum omitted

  frame.set(dnsPayload, 42);
  return frame;
}

// ─── generateWhisperingWireCapture ───────────────────────────────────────────

/**
 * Returns a valid classic pcap ArrayBuffer containing:
 *  - 1  DNS query  with a name > 40 chars and high Shannon entropy
 *  - 12 NXDOMAIN reply frames (rcode = 3) for the same client IP
 *  - 1  HTTP GET  with an Authorization: Basic header (cleartext credential)
 *  - 2  ARP reply frames claiming the same IP from two different MACs
 *
 * Triggers: SuspiciousDns (high), CleartextCredentials (high), ArpSpoofing (high).
 */
function generateWhisperingWireCapture() {
  const MAC_CLIENT = 'aa:bb:cc:11:22:33'; // 192.168.1.5  — client / victim host
  const MAC_DNS    = 'dd:ee:ff:44:55:66'; // 8.8.8.8      — DNS server
  const MAC_WEB    = '11:22:33:aa:bb:cc'; // 93.184.216.34 — web server
  const MAC_SPF1   = 'de:ad:be:ef:00:01'; // first  spoofer MAC
  const MAC_SPF2   = 'de:ad:be:ef:00:02'; // second spoofer MAC
  const MAC_VICTIM = 'ca:fe:ba:be:12:34'; // gateway being impersonated
  const BCAST      = 'ff:ff:ff:ff:ff:ff';

  const IP_CLIENT  = '192.168.1.5';
  const IP_DNS     = '8.8.8.8';
  const IP_WEB     = '93.184.216.34';
  const IP_SPOOFED = '192.168.1.100';     // the IP both spoofer MACs claim to own
  const IP_VICTIM  = '192.168.1.1';       // gateway whose IP is being spoofed

  // ── Suspicious DNS name ──────────────────────────────────────────────────
  // 40 hex chars + ".evil.com" = 49 chars total; hex character set gives
  // Shannon entropy ≈ 3.9 bits/char — well above the 3.5 threshold.
  const suspName = 'a3f9b2e1c7d4a8f2b1e9c3d7a4f8b2e1c9d3a7f1.evil.com';

  const dnsQueryMsg   = _buildDnsMessage(suspName, 0x0100); // standard query
  const dnsNxdomMsg   = _buildDnsMessage(suspName, 0x8183); // NXDOMAIN reply (rcode=3)

  // Query: client → DNS server, src port 1234, dst port 53
  const frameQuery = _buildDnsFrame(
    MAC_CLIENT, MAC_DNS, IP_CLIENT, IP_DNS, 1234, 53, dnsQueryMsg
  );

  // 12 NXDOMAIN replies: DNS server → client, src port 53, dst port 1234
  const nxdomainFrames = [];
  for (let i = 0; i < 12; i++) {
    nxdomainFrames.push(
      _buildDnsFrame(MAC_DNS, MAC_CLIENT, IP_DNS, IP_CLIENT, 53, 1234, dnsNxdomMsg)
    );
  }

  // ── HTTP cleartext credential ────────────────────────────────────────────
  // "dXNlcjpwYXNz" is base64("user:pass") — detectCleartextCredentials will
  // match the "Authorization: Basic " prefix and mask the credential.
  const httpPayload =
    'GET /admin HTTP/1.1\r\n' +
    'Host: evil.com\r\n' +
    'Authorization: Basic dXNlcjpwYXNz\r\n' +
    'Connection: close\r\n\r\n';
  // TCP flags PSH(0x08) + ACK(0x10) = 0x18; data offset byte = 0x50 (set by _buildTcpFrame)
  const frameHttp = _buildTcpFrame(
    MAC_CLIENT, MAC_WEB, IP_CLIENT, IP_WEB, 12345, 80, 0x18, httpPayload
  );

  // ── ARP spoofing ─────────────────────────────────────────────────────────
  // Two ARP replies both claiming IP_SPOOFED but with different sender MACs.
  // detectArpSpoofing maps ip → Set<mac> and fires when a set size ≥ 2.
  const frameArp1 = _buildArpFrame(
    MAC_SPF1, BCAST, 2, MAC_SPF1, IP_SPOOFED, MAC_VICTIM, IP_VICTIM
  );
  const frameArp2 = _buildArpFrame(
    MAC_SPF2, BCAST, 2, MAC_SPF2, IP_SPOOFED, MAC_VICTIM, IP_VICTIM
  );

  const frames = [frameQuery, ...nxdomainFrames, frameHttp, frameArp1, frameArp2];
  const totalFrameBytes = frames.reduce((sum, f) => sum + f.byteLength, 0);

  const bufSize = 24 + frames.length * 16 + totalFrameBytes;
  const buf = new ArrayBuffer(bufSize);
  const dv  = new DataView(buf);
  const u8  = new Uint8Array(buf);

  _writePcapFileHeader(dv, 0);

  let offset = 24;
  frames.forEach((frame, i) => {
    offset = _writePacketRecord(dv, u8, offset, 1000000 + i, 0, frame);
  });

  return buf;
}
