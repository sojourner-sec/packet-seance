// detectors.js — detection rules (pure functions, no DOM access)

// All detection thresholds in one place — easy to tune.
var THRESHOLDS = {
  portScanMinPorts: 15,
  portScanMaxHandshakeRatio: 0.1,
  pingSweepMinHosts: 10,
  dnsNxdomainBurst: 10,
  dnsLongNameLength: 40,
  dnsHighEntropy: 3.5,      // bits per character Shannon entropy
  arpSpoofMinMacs: 2
};

// Detector functions will be added here:
// detectPortScan(packets)         — task 5.2
// detectPingSweep(packets)        — task 5.4
// detectSuspiciousDns(packets)    — task 5.5
// detectCleartextCredentials(packets) — task 5.6
// detectArpSpoofing(packets)      — task 5.8
// runDetectors(packets)           — task 5.10

// detectPortScan — task 5.2
// Groups TCP SYN-only packets by src→dst IP pair. Flags pairs that probe
// enough distinct ports with too few completed handshakes (SYN+ACK replies).
function detectPortScan(packets) {
  // synPorts: { 'srcIp->dstIp': Set<dstPort> }
  // synCounts: { 'srcIp->dstIp': number }
  var synPorts  = {};
  var synCounts = {};

  // synAckCounts: keyed by 'dstIp->srcIp' (the responder side)
  var synAckCounts = {};

  for (var i = 0; i < packets.length; i++) {
    var pkt = packets[i];
    if (!pkt.ip || !pkt.tcp) continue;

    var src   = pkt.ip.src;
    var dst   = pkt.ip.dst;
    var flags = pkt.tcp.flags;

    if (flags.SYN && !flags.ACK) {
      // SYN-only: potential scan packet
      var key = src + '->' + dst;
      if (!synPorts[key])  synPorts[key]  = {};
      if (!synCounts[key]) synCounts[key] = 0;
      synPorts[key][pkt.tcp.dstPort] = true;
      synCounts[key]++;
    } else if (flags.SYN && flags.ACK) {
      // SYN+ACK: handshake reply from dst back to src
      var rkey = dst + '->' + src;  // map to the original scanner pair
      synAckCounts[rkey] = (synAckCounts[rkey] || 0) + 1;
    }
  }

  // Evaluate each src→dst pair
  var bestKey    = null;
  var bestPorts  = 0;

  var keys = Object.keys(synPorts);
  for (var j = 0; j < keys.length; j++) {
    var k          = keys[j];
    var portCount  = Object.keys(synPorts[k]).length;
    var synCount   = synCounts[k];
    var synAckCount = synAckCounts[k] || 0;
    var ratio      = synCount > 0 ? synAckCount / synCount : 0;

    if (portCount >= THRESHOLDS.portScanMinPorts &&
        ratio     <= THRESHOLDS.portScanMaxHandshakeRatio) {
      if (portCount > bestPorts) {
        bestPorts = portCount;
        bestKey   = k;
      }
    }
  }

  if (!bestKey) return null;

  var parts   = bestKey.split('->');
  var srcIp   = parts[0];
  var dstIp   = parts[1];

  return {
    type:        'PortScan',
    severity:    'high',
    hosts:       [srcIp, dstIp],
    evidence:    'Port scan: ' + bestPorts + ' ports probed from ' + srcIp + ' to ' + dstIp,
    packetCount: synCounts[bestKey]
  };
}

// detectPingSweep — groups ICMP echo request (type 8) packets by source IP.
// Returns a finding for the source with the most distinct destination IPs
// if that count meets THRESHOLDS.pingSweepMinHosts. Severity: medium.
function detectPingSweep(packets) {
  // sweepMap: srcIp -> { dsts: Set<string>, count: number }
  var sweepMap = {};

  for (var i = 0; i < packets.length; i++) {
    var pkt = packets[i];
    if (pkt.icmp && pkt.icmp.type === 8 && pkt.ip) {
      var src = pkt.ip.src;
      var dst = pkt.ip.dst;
      if (!sweepMap[src]) {
        sweepMap[src] = { dsts: new Set(), count: 0 };
      }
      sweepMap[src].dsts.add(dst);
      sweepMap[src].count++;
    }
  }

  // Find the source with the most distinct destinations that meets the threshold.
  var bestSrc = null;
  var bestSize = 0;
  var srcs = Object.keys(sweepMap);
  for (var j = 0; j < srcs.length; j++) {
    var s = srcs[j];
    var size = sweepMap[s].dsts.size;
    if (size >= THRESHOLDS.pingSweepMinHosts && size > bestSize) {
      bestSrc = s;
      bestSize = size;
    }
  }

  if (bestSrc === null) return null;

  return {
    type: 'PingSweep',
    severity: 'medium',
    hosts: [bestSrc],
    evidence: 'Ping sweep: ' + bestSize + ' hosts pinged from ' + bestSrc,
    packetCount: sweepMap[bestSrc].count
  };
}

// detectSuspiciousDns — task 5.5
// Flags long names, high-entropy names, and NXDOMAIN reply bursts.
function detectSuspiciousDns(packets) {
  // Shannon entropy of a string: H = -Σ pᵢ·log₂(pᵢ)
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    var freq = {};
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    var h = 0;
    var len = str.length;
    var chars = Object.keys(freq);
    for (var j = 0; j < chars.length; j++) {
      var p = freq[chars[j]] / len;
      h -= p * Math.log2(p);
    }
    return h;
  }

  var flaggedHosts   = {};   // ip → true  (sources of suspicious queries)
  var nxdomainCount  = {};   // ip (client/dst) → count of NXDOMAIN replies
  var suspiciousNames = [];  // first flagged name, for evidence string
  var packetCount    = 0;

  for (var i = 0; i < packets.length; i++) {
    var pkt = packets[i];
    if (!pkt.dns || !pkt.ip) continue;

    var name   = pkt.dns.name  || '';
    var rcode  = pkt.dns.rcode;
    var srcIp  = pkt.ip.src;
    var dstIp  = pkt.ip.dst;
    var flagged = false;

    // Long name check
    if (name.length > THRESHOLDS.dnsLongNameLength) {
      flagged = true;
      if (suspiciousNames.length === 0) suspiciousNames.push(name);
    }

    // High-entropy name check
    if (!flagged && shannonEntropy(name) > THRESHOLDS.dnsHighEntropy) {
      flagged = true;
      if (suspiciousNames.length === 0) suspiciousNames.push(name);
    }

    if (flagged) {
      flaggedHosts[srcIp] = true;
      packetCount++;
    }

    // NXDOMAIN reply: rcode 3; the client is the destination of the reply
    if (rcode === 3) {
      nxdomainCount[dstIp] = (nxdomainCount[dstIp] || 0) + 1;
    }
  }

  // Check for NXDOMAIN bursts
  var nxdomainHosts = [];
  var nxClients = Object.keys(nxdomainCount);
  for (var k = 0; k < nxClients.length; k++) {
    var client = nxClients[k];
    if (nxdomainCount[client] >= THRESHOLDS.dnsNxdomainBurst) {
      nxdomainHosts.push(client);
      flaggedHosts[client] = true;
      packetCount += nxdomainCount[client];
    }
  }

  var hosts = Object.keys(flaggedHosts);
  if (hosts.length === 0) return null;

  // Build a readable evidence string
  var evidenceParts = [];
  if (suspiciousNames.length > 0) {
    var displayName = suspiciousNames[0];
    // Truncate very long names for readability
    if (displayName.length > 60) displayName = displayName.slice(0, 57) + '...';
    evidenceParts.push("long/high-entropy name '" + displayName + "'");
  }
  for (var n = 0; n < nxdomainHosts.length; n++) {
    evidenceParts.push(nxdomainCount[nxdomainHosts[n]] + ' NXDOMAIN replies to ' + nxdomainHosts[n]);
  }

  return {
    type:        'SuspiciousDns',
    severity:    'high',
    hosts:       hosts,
    evidence:    'Suspicious DNS: ' + evidenceParts.join(', '),
    packetCount: packetCount
  };
}

// detectArpSpoofing — task 5.8
// Builds ip → Set<mac> from ARP reply packets (op=2).
// Returns a finding if any IP appears with ≥ arpSpoofMinMacs distinct MACs.
function detectArpSpoofing(packets) {
  // ipMacs: senderIp -> Set<senderMac>
  var ipMacs = {};
  var totalArpReplies = 0;

  for (var i = 0; i < packets.length; i++) {
    var pkt = packets[i];
    if (pkt.arp && pkt.arp.op === 2) {
      totalArpReplies++;
      var ip  = pkt.arp.senderIp;
      var mac = pkt.arp.senderMac;
      if (!ipMacs[ip]) ipMacs[ip] = {};
      ipMacs[ip][mac] = true;
    }
  }

  // Find the IP with the most distinct MACs that meets the threshold.
  var worstIp   = null;
  var worstMacs = null;
  var worstSize = 0;

  var ips = Object.keys(ipMacs);
  for (var j = 0; j < ips.length; j++) {
    var ip   = ips[j];
    var macs = Object.keys(ipMacs[ip]);
    if (macs.length >= THRESHOLDS.arpSpoofMinMacs && macs.length > worstSize) {
      worstIp   = ip;
      worstMacs = macs;
      worstSize = macs.length;
    }
  }

  if (!worstIp) return null;

  return {
    type:        'ArpSpoofing',
    severity:    'high',
    hosts:       worstMacs.concat([worstIp]),
    evidence:    'ARP spoofing: IP ' + worstIp + ' claimed by ' + worstSize +
                 ' MACs: ' + worstMacs.join(', '),
    packetCount: totalArpReplies
  };
}

// detectCleartextCredentials — task 5.6
// Scans TCP payloads for HTTP Basic auth, HTTP password= form fields, and FTP
// USER/PASS commands. Credentials are masked before storing; raw values are
// never retained.
function detectCleartextCredentials(packets) {
  var hostsSet   = {};   // unique IPs involved
  var count      = 0;    // packets containing at least one credential
  var firstKind  = '';   // description used in evidence (first match wins)
  var firstMask  = '';   // masked credential value for evidence
  var firstPort  = 0;

  // Mask a credential: first ≤4 chars visible, rest replaced with ****.
  function maskCred(value) {
    var visible = value.slice(0, 4);
    return visible + '****';
  }

  for (var i = 0; i < packets.length; i++) {
    var pkt = packets[i];
    if (!pkt.tcp || !pkt.tcp.payload || pkt.tcp.payload.length === 0) continue;

    var text;
    try {
      text = new TextDecoder('utf-8', { fatal: false }).decode(pkt.tcp.payload);
    } catch (e) {
      continue;
    }

    var matched   = false;
    var kind      = '';
    var masked    = '';
    var port      = pkt.tcp.dstPort;

    // 1. HTTP Authorization: Basic <base64>
    var basicMatch = text.match(/Authorization:\s*Basic\s+(\S+)/i);
    if (basicMatch) {
      kind    = 'HTTP Basic';
      masked  = maskCred(basicMatch[1]);
      matched = true;
    }

    // 2. HTTP form body: password=<value>
    if (!matched) {
      var pwMatch = text.match(/(?:^|&|\?)password=([^&\s\r\n]*)/i);
      if (pwMatch && pwMatch[1].length > 0) {
        kind    = 'HTTP password field';
        masked  = maskCred(pwMatch[1]);
        matched = true;
      }
    }

    // 3. FTP PASS <password>
    if (!matched) {
      var ftpPass = text.match(/^PASS\s+(\S+)/im);
      if (ftpPass) {
        kind    = 'FTP PASS';
        masked  = maskCred(ftpPass[1]);
        port    = pkt.tcp.dstPort;
        matched = true;
      }
    }

    // 4. FTP USER <username>
    if (!matched) {
      var ftpUser = text.match(/^USER\s+(\S+)/im);
      if (ftpUser) {
        kind    = 'FTP USER';
        masked  = maskCred(ftpUser[1]);
        port    = pkt.tcp.dstPort;
        matched = true;
      }
    }

    if (matched) {
      count++;
      if (pkt.ip) {
        hostsSet[pkt.ip.src] = true;
        hostsSet[pkt.ip.dst] = true;
      }
      // Capture first match details for evidence string.
      if (firstKind === '') {
        firstKind = kind;
        firstMask = masked;
        firstPort = port;
      }
    }
  }

  if (count === 0) return null;

  return {
    type:        'CleartextCredentials',
    severity:    'high',
    hosts:       Object.keys(hostsSet),
    evidence:    'Cleartext credentials: ' + firstKind + " '" + firstMask + "' on port " + firstPort,
    packetCount: count
  };
}

// runDetectors — task 5.10
// Calls all five detectors and returns the array of non-null results.
function runDetectors(packets) {
  var results = [];
  var detectors = [
    detectPortScan,
    detectPingSweep,
    detectSuspiciousDns,
    detectCleartextCredentials,
    detectArpSpoofing
  ];
  for (var i = 0; i < detectors.length; i++) {
    var finding = detectors[i](packets);
    if (finding !== null) {
      results.push(finding);
    }
  }
  return results;
}
