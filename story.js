// story.js — narrative template functions (pure, no DOM access)
// All functions return plain strings. Callers must use textContent, not innerHTML.

// --- helpers ---

// Format a duration in seconds into a human-readable string.
function _formatDuration(seconds) {
  if (!seconds || seconds <= 0) return 'a fleeting moment';
  if (seconds < 2)  return 'less than a second';
  if (seconds < 60) return Math.round(seconds) + ' seconds';
  var mins = Math.floor(seconds / 60);
  var secs = Math.round(seconds % 60);
  return mins + ' minute' + (mins > 1 ? 's' : '') +
         (secs > 0 ? ' and ' + secs + ' second' + (secs > 1 ? 's' : '') : '');
}

// Describe the dominant protocol from a protocolCounts object.
function _dominantProtocol(counts) {
  if (!counts) return 'ethereal';
  var order = ['tcp', 'dns', 'udp', 'icmp', 'arp', 'ipv4'];
  var best  = 'unknown';
  var bestN = 0;
  for (var i = 0; i < order.length; i++) {
    var n = counts[order[i]] || 0;
    if (n > bestN) { bestN = n; best = order[i]; }
  }
  var labels = {
    tcp: 'TCP conversations', dns: 'DNS whispers', udp: 'UDP datagrams',
    icmp: 'ICMP echoes', arp: 'ARP exchanges', ipv4: 'IP exchanges'
  };
  return labels[best] || 'unknown traffic';
}

// Return the first topTalker IP, or a placeholder string.
function _firstTalker(topTalkers) {
  return (topTalkers && topTalkers.length > 0) ? topTalkers[0].ip : 'an unnamed host';
}

// Safely pick a host from a hosts array, falling back to a placeholder.
function _host(hosts, index) {
  return (hosts && hosts[index]) ? hosts[index] : 'an unknown host';
}

// --- generateSummaryStory ---

// Returns a short, harmless ghost-story paragraph framing the traffic summary.
// Always returns a non-empty string.
function generateSummaryStory(summary) {
  var total    = (summary && summary.totalPackets)   || 0;
  var dur      = (summary && summary.durationSeconds) || 0;
  var proto    = _dominantProtocol(summary && summary.protocolCounts);
  var talker   = _firstTalker(summary && summary.topTalkers);
  var skipped  = (summary && summary.skipped) || 0;
  var truncMsg = (summary && summary.truncated)
    ? ' The séance could only observe the first 50,000 packets — the rest dissolved into the ether.'
    : '';

  if (total === 0) {
    return 'The crystal reveals an empty silence — not a single packet stirs in the ether. ' +
           'The network holds its breath, waiting for the living to arrive.';
  }

  var skippedNote = skipped > 0
    ? ' ' + skipped + ' malformed phantoms slipped through the veil unread, their shapes too broken to decode.'
    : '';

  return 'The crystal grows cloudy. Within its depths, ' + total + ' packets drift through ' +
         _formatDuration(dur) + ' of captured time — mostly ' + proto + ', ' +
         'their purposes appearing perfectly ordinary. ' +
         'The most restless presence is ' + talker + ', whose voice carries further than the rest. ' +
         'All seems peaceful, the wire humming with the quiet routines of the living.' +
         skippedNote + truncMsg;
}

// --- generateFindingStory ---

// Returns { story, explanation, tip } for the given finding.
// All three fields are always non-empty strings.
function generateFindingStory(finding) {
  if (!finding) {
    return {
      story:       'A shapeless presence disturbs the ether, its nature unclear.',
      explanation: 'An unknown anomaly was detected in the capture.',
      tip:         'Review the capture manually for unusual traffic patterns.'
    };
  }

  var hosts = finding.hosts || [];
  var pkt   = finding.packetCount || 0;
  var ev    = finding.evidence   || '';

  switch (finding.type) {

    case 'PortScan': {
      var scanner = _host(hosts, 0);
      var target  = _host(hosts, 1);
      return {
        story: 'In the small hours, ' + scanner + ' moved through the corridors of ' + target +
               ' like a figure trying every locked door. ' +
               pkt + ' knocks were counted, each one testing a different threshold, ' +
               'probing for any entrance left unguarded. ' +
               'The house gave almost nothing back — but the visitor made note of every latch.',
        explanation: 'A port scan occurred. ' + scanner + ' sent TCP SYN packets to many different ' +
               'ports on ' + target + ', mapping which services are reachable. ' +
               'Evidence: ' + ev + '.',
        tip:   'Block unused ports with a firewall and configure your intrusion detection ' +
               'system to alert on SYN floods or rapid sequential port connections from one source.'
      };
    }

    case 'PingSweep': {
      var sweeper = _host(hosts, 0);
      return {
        story: 'A lantern moved slowly across the grounds. ' + sweeper + ' sent an ICMP echo ' +
               'into the dark, then another, and another — ' + pkt + ' in all, each aimed at a ' +
               'different address, illuminating whatever hosts chose to answer. ' +
               'The sweep was methodical, the silence between echoes deliberate.',
        explanation: 'A ping sweep occurred. ' + sweeper + ' sent ICMP echo requests (ping) to ' +
               'many different IP addresses to discover which hosts are alive on the network. ' +
               'Evidence: ' + ev + '.',
        tip:   'Restrict or rate-limit ICMP echo requests at the perimeter. ' +
               'Segment your network so that internal hosts are not reachable from untrusted segments.'
      };
    }

    case 'SuspiciousDns': {
      var dnsHost = _host(hosts, 0);
      return {
        story: 'Strange syllables were whispered into the DNS. Names of impossible length, ' +
               'or names assembled from no recognisable tongue, drifted outward from ' + dnsHost + '. ' +
               'Such queries carry meaning only to those who already know the answer — ' +
               'a channel disguised as ordinary curiosity. ' +
               pkt + ' packets bore these unsettling names into the dark.',
        explanation: 'Suspicious DNS activity was detected. Long domain names or names with high ' +
               'randomness (entropy) can indicate DNS tunnelling — a technique used to smuggle data ' +
               'past firewalls. Bursts of NXDOMAIN replies may indicate beaconing to a command-and-control server. ' +
               'Evidence: ' + ev + '.',
        tip:   'Monitor DNS query lengths and entropy scores. Block or alert on known DNS tunnelling ' +
               'patterns, and consider a DNS firewall that flags newly registered or low-reputation domains.'
      };
    }

    case 'CleartextCredentials': {
      var sender   = _host(hosts, 0);
      var receiver = _host(hosts, 1);
      return {
        story: 'A letter passed between ' + sender + ' and ' + receiver + ', its seal unbroken ' +
               'yet its words written plainly enough for any observer to read. ' +
               'Within the envelope lay credentials — a name, a secret — offered to the wire ' +
               'without ceremony or concealment. ' +
               'Anyone present on the wire could have made a copy.',
        explanation: 'Credentials were transmitted in cleartext. HTTP Basic auth, an unencrypted ' +
               'password form field, or FTP login commands expose usernames and passwords to anyone ' +
               'who can observe the network traffic. Evidence: ' + ev + '.',
        tip:   'Replace plaintext protocols with TLS-encrypted equivalents (HTTPS, FTPS/SFTP). ' +
               'Eliminate HTTP Basic authentication; prefer token-based auth over encrypted connections.'
      };
    }

    case 'ArpSpoofing': {
      var claimedIp = hosts[hosts.length - 1] || 'an unknown IP';
      var mac1      = _host(hosts, 0);
      var mac2      = _host(hosts, 1);
      return {
        story: 'Two voices both claimed the same name. The address ' + claimedIp + ' was declared, ' +
               'in the same breath, to belong to ' + mac1 + ' and to ' + mac2 + '. ' +
               'An impostor had stepped into another\'s identity, and for a time, ' +
               'the network believed them both.',
        explanation: 'ARP spoofing was detected. One IP address was claimed by multiple different ' +
               'MAC addresses in ARP reply packets. An attacker can forge ARP replies to redirect ' +
               'traffic through their own machine — a classic man-in-the-middle position. ' +
               'Evidence: ' + ev + '.',
        tip:   'Enable Dynamic ARP Inspection (DAI) on managed switches to validate ARP packets ' +
               'against a trusted binding table. On critical segments, use static ARP entries for gateway addresses.'
      };
    }

    default: {
      return {
        story:       'An unnamed presence made itself known in ' + pkt + ' packets. ' +
                     'Its nature resists classification, but its passage left a mark.',
        explanation: 'An unrecognised finding type was returned by the detectors. Evidence: ' + ev + '.',
        tip:         'Examine the raw packets manually in a tool such as Wireshark for further analysis.'
      };
    }
  }
}

// --- generatePeacefulStory ---

// Returns a short, calm story for a clean capture with no findings.
// Always returns a non-empty string.
function generatePeacefulStory(summary) {
  var total  = (summary && summary.totalPackets)    || 0;
  var dur    = (summary && summary.durationSeconds)  || 0;
  var talker = _firstTalker(summary && summary.topTalkers);
  var proto  = _dominantProtocol(summary && summary.protocolCounts);

  if (total === 0) {
    return 'The séance finds only stillness. No packet stirs, no spirit lingers. ' +
           'This network is at perfect rest.';
  }

  return 'The séance is complete, and the wire holds no darkness tonight. ' +
         'Across ' + _formatDuration(dur) + ', ' + total + ' packets moved through the ether — ' +
         'quiet ' + proto + ', the ordinary breath of a network at ease. ' +
         'The most present voice was ' + talker + ', faithful and unremarkable. ' +
         'No shadow followed its transmissions. Sleep soundly; the house is still.';
}
