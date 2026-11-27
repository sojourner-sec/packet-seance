// =============================================================================
// app.js — Packet Séance state machine, UI wiring, and pcap pipeline
// Depends (in load order): samples.js, pcap.js, detectors.js, story.js, audio.js
// =============================================================================

// ─── Zone positions for the planchette ───────────────────────────────────────

const ZONE_POSITIONS = {
  recon:     { x: '15%', y: '30%' },
  dns:       { x: '35%', y: '55%' },
  cleartext: { x: '55%', y: '30%' },
  lateral:   { x: '75%', y: '55%' },
  critical:  { x: '45%', y: '75%' },
};

// Map finding type strings to spirit-board zone names.
const FINDING_ZONES = {
  PortScan:             'recon',
  PingSweep:            'recon',
  SuspiciousDns:        'dns',
  CleartextCredentials: 'cleartext',
  ArpSpoofing:          'lateral',
};

// ─── Application state (8.1) ─────────────────────────────────────────────────

let state = {
  phase:         'idle',   // 'idle' | 'summoning' | 'calm' | 'strike'
  packets:       null,     // DecodedPacket[] | null
  summary:       null,     // Summary | null
  findings:      [],       // Finding[]
  droneHandle:   null,     // { stop: function } | null
  strikeArmed:   false,
  strikeTimer:   null,
  strikeFired:   false,
  _pendingBuffer: null,    // ArrayBuffer stored when file is loaded but not yet summoned
  _pcapngTimer:  null,     // auto-hide timer for #pcapng-msg
  _errorTimer:   null,     // auto-hide timer for #error-msg
};

// ─── Phase helper ─────────────────────────────────────────────────────────────

function setPhase(phase) {
  document.body.dataset.phase = phase;
  state.phase = phase;
}

// ─── Planchette movement ──────────────────────────────────────────────────────

function setPlanchetteZone(zone) {
  const planchette = document.getElementById('planchette');
  if (!planchette) return;
  const pos = ZONE_POSITIONS[zone];
  if (!pos) return;
  planchette.style.transform =
    'translate(calc(' + pos.x + ' - 50%), calc(' + pos.y + ' - 50%))';
}

// ─── Message helpers ──────────────────────────────────────────────────────────

// Show the "no file" notice for 3 s without changing state.phase (8.11 / task spec).
function showEmptyInputMessage() {
  const msg = document.getElementById('empty-input-msg');
  if (!msg) return;
  msg.hidden = false;
  setTimeout(function () { msg.hidden = true; }, 3000);
}

// Show the pcapng notice for 6 s; phase stays 'idle' (8.8).
function showPcapngMessage() {
  const el = document.getElementById('pcapng-msg');
  if (!el) return;
  // Cancel any in-flight hide timer so a repeat call restarts the countdown.
  if (state._pcapngTimer !== null) {
    clearTimeout(state._pcapngTimer);
  }
  el.hidden = false;
  state._pcapngTimer = setTimeout(function () {
    el.hidden = true;
    state._pcapngTimer = null;
  }, 6000);
}

// Show a generic error message for 5 s; phase stays 'idle' (8.8).
function showErrorMessage(msg) {
  const el = document.getElementById('error-msg');
  if (!el) return;
  // Cancel any in-flight hide timer so a repeat call restarts the countdown.
  if (state._errorTimer !== null) {
    clearTimeout(state._errorTimer);
  }
  if (msg) el.textContent = msg;
  el.hidden = false;
  state._errorTimer = setTimeout(function () {
    el.hidden = true;
    state._errorTimer = null;
  }, 5000);
}

// ─── Clipboard helpers ────────────────────────────────────────────────────────

function showCopyConfirmation() {
  const confirm = document.getElementById('copy-confirm');
  if (!confirm) return;
  confirm.hidden = false;
  setTimeout(function () { confirm.hidden = true; }, 1500);
}

function _fallbackCopy(text) {
  try {
    const temp = document.createElement('textarea');
    temp.value = text;
    temp.style.position = 'fixed';
    temp.style.opacity  = '0';
    document.body.appendChild(temp);
    temp.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(temp);
    if (ok) { showCopyConfirmation(); return; }
  } catch (_) {}
  // Last resort: visually select the summary panel text.
  const panel = document.getElementById('summary-panel');
  if (panel) {
    const range = document.createRange();
    range.selectNodeContents(panel);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  }
}

// ─── Visual flash ─────────────────────────────────────────────────────────────

function triggerFlash() {
  document.body.classList.add('invert-flash');
  setTimeout(function () {
    document.body.classList.remove('invert-flash');
  }, 250);
}

// ─── Pointer proximity — immediate strike trigger ─────────────────────────────

function pointerNearInput() {
  if (state.strikeArmed && !state.strikeFired && state.phase === 'calm') {
    _triggerStrike();
  }
}

// ─── copySummary (8.4) ────────────────────────────────────────────────────────

function copySummary() {
  if (state.phase !== 'calm') return;

  const panel = document.getElementById('summary-panel');
  const text  = panel ? panel.textContent : '';

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(showCopyConfirmation)
      .catch(function () { _fallbackCopy(text); });
  } else {
    _fallbackCopy(text);
  }

  // Arm the delayed strike on first copy click.
  if (state.strikeArmed && !state.strikeFired && state.strikeTimer === null) {
    state.strikeTimer = setTimeout(_triggerStrike, 4000);
  }
}

// ─── showSummary (8.6) ────────────────────────────────────────────────────────

function showSummary(summary, storyText) {
  const panel = document.getElementById('summary-panel');
  if (!panel) return;

  // Clear any previous content from the summary panel.
  while (panel.firstChild) panel.removeChild(panel.firstChild);

  // Also clear findings list from any previous run.
  const prevFindings = document.getElementById('findings-list');
  if (prevFindings) {
    while (prevFindings.firstChild) prevFindings.removeChild(prevFindings.firstChild);
    prevFindings.hidden = true;
  }

  // Packet count + duration heading.
  // Duration is formatted to one decimal place with an 's' suffix, e.g. "3.2 s".
  const hdr = document.createElement('p');
  const dur = summary.durationSeconds > 0
    ? (Math.round(summary.durationSeconds * 10) / 10).toFixed(1) + ' s'
    : 'a fleeting moment';
  hdr.textContent = summary.totalPackets + ' packets over ' + dur;
  hdr.className   = 'summary-header';
  panel.appendChild(hdr);

  // Protocol breakdown.
  const protoHdr = document.createElement('p');
  protoHdr.textContent = 'Protocols detected:';
  protoHdr.className   = 'summary-section-label';
  panel.appendChild(protoHdr);

  const counts  = summary.protocolCounts || {};
  const protos  = ['tcp', 'udp', 'dns', 'icmp', 'arp', 'ipv4', 'unknown'];
  const protoList = document.createElement('ul');
  protoList.className = 'summary-list';
  protos.forEach(function (proto) {
    const n = counts[proto] || 0;
    if (n === 0) return;
    const li = document.createElement('li');
    li.textContent = proto.toUpperCase() + ': ' + n;
    protoList.appendChild(li);
  });
  if (protoList.childNodes.length > 0) panel.appendChild(protoList);

  // Top talkers (up to 5).
  const talkers = summary.topTalkers || [];
  if (talkers.length > 0) {
    const talkHdr = document.createElement('p');
    talkHdr.textContent = 'Top talkers:';
    talkHdr.className   = 'summary-section-label';
    panel.appendChild(talkHdr);

    const talkList = document.createElement('ul');
    talkList.className = 'summary-list';
    talkers.slice(0, 5).forEach(function (t) {
      const li = document.createElement('li');
      li.textContent = t.ip + ' — ' + t.count + ' packets';
      talkList.appendChild(li);
    });
    panel.appendChild(talkList);
  }

  // Truncation / skipped notice.
  if (summary.truncated) {
    const truncNote = document.createElement('p');
    truncNote.textContent = 'Note: capture truncated to 50,000 packets.';
    truncNote.className   = 'summary-note';
    panel.appendChild(truncNote);
  }
  if (summary.skipped > 0) {
    const skipNote = document.createElement('p');
    skipNote.textContent = summary.skipped + ' malformed packets skipped.';
    skipNote.className   = 'summary-note';
    panel.appendChild(skipNote);
  }

  // Ghost-story paragraph.
  const story = document.createElement('p');
  story.textContent = storyText;
  story.className   = 'summary-story';
  panel.appendChild(story);

  // Reveal panels.
  const resultPanel = document.getElementById('result-panel');
  if (resultPanel) resultPanel.hidden = false;
  panel.hidden = false;

  // Show the copy row.
  const copyRow = document.querySelector('.copy-row');
  if (copyRow) copyRow.hidden = false;
}

// ─── showFindings (8.7) ───────────────────────────────────────────────────────

// Convert camelCase type name to spaced words: 'PortScan' → 'Port Scan'.
function _typeToLabel(type) {
  return type.replace(/([A-Z])/g, ' $1').trim();
}

function showFindings(findings) {
  const list = document.getElementById('findings-list');
  if (!list) return;

  // Clear previous content.
  while (list.firstChild) list.removeChild(list.firstChild);

  // Peaceful capture — no findings.
  if (!findings || findings.length === 0) {
    const p = document.createElement('p');
    p.textContent = generatePeacefulStory(state.summary);
    p.className   = 'peaceful-story';
    list.appendChild(p);
    list.hidden = false;
    return;
  }

  findings.forEach(function (finding) {
    const narratives = generateFindingStory(finding);

    const card = document.createElement('div');
    card.className = 'finding';

    const title = document.createElement('h3');
    title.textContent = _typeToLabel(finding.type || 'Unknown');
    card.appendChild(title);

    const badge = document.createElement('span');
    badge.className   = 'severity-badge';
    badge.textContent = finding.severity || '';
    card.appendChild(badge);

    const storyP = document.createElement('p');
    storyP.className   = 'finding-story';
    storyP.textContent = narratives.story;
    card.appendChild(storyP);

    const explP = document.createElement('p');
    explP.className   = 'finding-explanation';
    explP.textContent = narratives.explanation;
    card.appendChild(explP);

    const tipP = document.createElement('p');
    tipP.className   = 'finding-tip';
    tipP.textContent = narratives.tip;
    card.appendChild(tipP);

    list.appendChild(card);

    // Highlight the matching board zone.
    const zoneName = FINDING_ZONES[finding.type];
    if (zoneName) {
      const zoneEl = document.querySelector('[data-zone="' + zoneName + '"]');
      if (zoneEl) zoneEl.classList.add('board-zone--active');
    }
  });

  list.hidden = false;
}

// ─── _tensionComplete (8.5) ───────────────────────────────────────────────────

function _tensionComplete() {
  if (state.phase !== 'summoning') return;

  if (state.droneHandle) {
    state.droneHandle.stop();
    state.droneHandle = null;
  }

  setPhase('calm');
  document.body.classList.add('parchment-mode');
  showSummary(state.summary, generateSummaryStory(state.summary));
}

// ─── _triggerStrike (8.9) ─────────────────────────────────────────────────────

function _triggerStrike() {
  if (state.strikeFired) return;
  state.strikeFired = true;

  if (state.strikeTimer !== null) {
    clearTimeout(state.strikeTimer);
    state.strikeTimer = null;
  }

  setPhase('strike');
  triggerFlash();
  playSting();
  setPlanchetteZone('critical');

  setTimeout(function () {
    showFindings(state.findings);
  }, 300);
}

// ─── summon (8.3) ─────────────────────────────────────────────────────────────

function summon(arrayBuffer) {
  if (state.phase !== 'idle') return;

  if (!arrayBuffer) {
    showEmptyInputMessage();
    return;
  }

  // Initialise audio on this user gesture.
  initAudio();

  // Parse the pcap file.
  let parseResult;
  try {
    parseResult = parsePcap(arrayBuffer);
  } catch (err) {
    if (err && err.type === 'PCAPNG') {
      showPcapngMessage();
    } else {
      showErrorMessage('The spirits cannot parse this file\u2026');
    }
    return;
  }

  // Run analysis.
  state.packets  = parseResult.packets;
  state.summary  = buildSummary(state.packets, {
    skipped:   parseResult.skipped,
    truncated: parseResult.truncated
  });
  state.findings = runDetectors(state.packets);

  state.strikeArmed  = state.findings.some(function (f) { return f.severity === 'high'; });
  state.strikeFired  = false;
  state.strikeTimer  = null;

  setPhase('summoning');

  // Walk the planchette through the first four zones.
  const walkZones = ['recon', 'dns', 'cleartext', 'lateral'];
  const stepMs    = 600;
  walkZones.forEach(function (zone, i) {
    setTimeout(function () { setPlanchetteZone(zone); }, i * stepMs);
  });

  // Rising drone for ~3 s.
  state.droneHandle = playDrone(3);

  // Transition to calm after 3 s.
  setTimeout(_tensionComplete, 3000);
}

// ─── copySummary alias already defined above ──────────────────────────────────

// ─── reset (8.10) ─────────────────────────────────────────────────────────────

function reset() {
  if (state.strikeTimer !== null) {
    clearTimeout(state.strikeTimer);
  }
  if (state._pcapngTimer !== null) {
    clearTimeout(state._pcapngTimer);
    state._pcapngTimer = null;
  }
  if (state._errorTimer !== null) {
    clearTimeout(state._errorTimer);
    state._errorTimer = null;
  }
  stopAll();

  // Reset state.
  state.phase        = 'idle';
  state.packets      = null;
  state.summary      = null;
  state.findings     = [];
  state.droneHandle  = null;
  state.strikeArmed  = false;
  state.strikeTimer  = null;
  state.strikeFired  = false;
  state._pendingBuffer = null;
  state._pcapngTimer = null;
  state._errorTimer  = null;

  document.body.dataset.phase = 'idle';
  document.body.classList.remove('parchment-mode');

  // Hide result panels.
  const toHide = ['result-panel', 'summary-panel', 'findings-list',
                   'pcapng-msg', 'error-msg', 'hidden-finding', 'empty-input-msg'];
  toHide.forEach(function (id) {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
  });

  // Clear dynamic content.
  const findingsList = document.getElementById('findings-list');
  if (findingsList) {
    while (findingsList.firstChild) findingsList.removeChild(findingsList.firstChild);
  }
  const summaryPanel = document.getElementById('summary-panel');
  if (summaryPanel) {
    while (summaryPanel.firstChild) summaryPanel.removeChild(summaryPanel.firstChild);
  }

  // Remove active highlights from all board zones.
  const zones = document.querySelectorAll('[data-zone]');
  zones.forEach(function (z) { z.classList.remove('board-zone--active'); });

  // Move planchette back to starting position.
  setPlanchetteZone('recon');

  // Allow the same file to be re-selected.
  const fileInput = document.getElementById('file-input');
  if (fileInput) fileInput.value = '';

  // Hide copy confirmation.
  const copyConfirm = document.getElementById('copy-confirm');
  if (copyConfirm) copyConfirm.hidden = true;

  // Reset drop-zone label to default text.
  _resetDropZoneLabel();
}

// ─── Drop-zone label helper ────────────────────────────────────────────────────

function _resetDropZoneLabel() {
  // Restore the original label text if it was modified by a sample load.
  const dropLabel = document.querySelector('.drop-zone__label');
  if (!dropLabel) return;
  // Rebuild the original label content.
  while (dropLabel.firstChild) dropLabel.removeChild(dropLabel.firstChild);

  const textNode = document.createTextNode('Drop your ');
  dropLabel.appendChild(textNode);

  const extSpan = document.createElement('span');
  extSpan.className   = 'drop-zone__ext';
  extSpan.textContent = '.pcap';
  dropLabel.appendChild(extSpan);

  dropLabel.appendChild(document.createTextNode(' file here, or '));

  const linkSpan = document.createElement('span');
  linkSpan.className   = 'drop-zone__link';
  linkSpan.textContent = 'browse\u2026';
  dropLabel.appendChild(linkSpan);

  // Re-append the file input (it was inside the label originally).
  const fileInput = document.getElementById('file-input');
  if (fileInput) dropLabel.appendChild(fileInput);
}

// ─── loadSampleCapture (8.11) ─────────────────────────────────────────────────

function loadSampleCapture(name, buffer) {
  initAudio();

  // Show the sample name in the drop-zone label.
  const dropLabel = document.querySelector('.drop-zone__label');
  if (dropLabel) {
    while (dropLabel.firstChild) dropLabel.removeChild(dropLabel.firstChild);

    const nameSpan = document.createElement('span');
    nameSpan.textContent = name + ' loaded';
    dropLabel.appendChild(nameSpan);

    // Count packets without throwing.
    try {
      const parsed = parsePcap(buffer);
      const countSpan = document.createElement('span');
      countSpan.textContent = ' (' + parsed.packets.length + ' packets)';
      dropLabel.appendChild(countSpan);
    } catch (_) {}
  }

  state._pendingBuffer = buffer;
  summon(buffer);
}

// ─── File-load helpers (8.2) ──────────────────────────────────────────────────

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

function _readFileAsBuffer(file) {
  if (file.size > MAX_FILE_SIZE) {
    showErrorMessage('The spirits are overwhelmed\u2026 Please use a file under 5\u00a0MB.');
    return;
  }
  const reader = new FileReader();
  reader.onload = function (e) {
    state._pendingBuffer = e.target.result;
    summon(e.target.result);
  };
  reader.onerror = function () {
    showErrorMessage('The ether rejects this offering\u2026 The file could not be read.');
  };
  reader.readAsArrayBuffer(file);
}

// ─── DOMContentLoaded — wire all events ──────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {

  // ── File input (8.2) ────────────────────────────────────────────────────────
  const fileInput = document.getElementById('file-input');
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      _readFileAsBuffer(file);
    });
  }

  // ── Drag-and-drop on drop-zone (8.2) ────────────────────────────────────────
  const dropZone = document.getElementById('drop-zone');
  if (dropZone) {
    dropZone.addEventListener('dragenter', function (e) {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragover', function (e) {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', function () {
      dropZone.classList.remove('drag-over');
    });
    dropZone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      _readFileAsBuffer(file);
    });

    // Keyboard activation: Enter or Space → trigger file input click (8.2).
    dropZone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const fi = document.getElementById('file-input');
        if (fi) fi.click();
      }
    });

    // Pointer near drop zone triggers strike when in calm phase.
    dropZone.addEventListener('pointermove', pointerNearInput);
  }

  // ── Summon button ────────────────────────────────────────────────────────────
  const summonBtn = document.getElementById('summon-btn');
  if (summonBtn) {
    summonBtn.addEventListener('click', function () {
      initAudio();
      if (state._pendingBuffer) {
        summon(state._pendingBuffer);
      } else {
        showEmptyInputMessage();
      }
    });
  }

  // ── Copy Summary button ───────────────────────────────────────────────────────
  const copySummaryBtn = document.getElementById('copy-summary-btn');
  if (copySummaryBtn) {
    copySummaryBtn.addEventListener('click', copySummary);
  }

  // ── Reset button ──────────────────────────────────────────────────────────────
  const resetBtn = document.getElementById('reset-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', reset);
  }

  // ── Mute toggle ───────────────────────────────────────────────────────────────
  const muteBtn = document.getElementById('mute-btn');
  if (muteBtn) {
    muteBtn.addEventListener('click', function () {
      const isMuted = muteBtn.getAttribute('aria-pressed') === 'true';
      setMute(!isMuted);
      muteBtn.textContent = isMuted ? '🔊 Mute' : '🔇 Unmute';
      muteBtn.setAttribute('aria-pressed', String(!isMuted));
      muteBtn.setAttribute('aria-label', isMuted ? 'Mute audio' : 'Unmute audio');
    });
  }

  // ── Sample capture buttons (8.11) ─────────────────────────────────────────────
  const sampleQuiet = document.getElementById('sample-quiet');
  if (sampleQuiet) {
    sampleQuiet.addEventListener('click', function () {
      loadSampleCapture('The Quiet House', generateQuietHouseCapture());
    });
  }

  const sampleKnocking = document.getElementById('sample-knocking');
  if (sampleKnocking) {
    sampleKnocking.addEventListener('click', function () {
      loadSampleCapture('The Knocking Visitor', generateKnockingVisitorCapture());
    });
  }

  const sampleWhispering = document.getElementById('sample-whispering');
  if (sampleWhispering) {
    sampleWhispering.addEventListener('click', function () {
      loadSampleCapture('The Whispering Wire', generateWhisperingWireCapture());
    });
  }

});
