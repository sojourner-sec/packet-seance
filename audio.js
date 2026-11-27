// =============================================================================
// audio.js — Web Audio synthesizer and mute control
// All functions are plain globals. No ES module syntax.
// All audio functions are no-ops when audioDisabled is true or _audioContext is null.
// =============================================================================

// --- Module-level vars -------------------------------------------------------

/** @type {AudioContext|null} */
var _audioContext = null;

/** @type {GainNode|null} */
var _masterGain = null;

var audioDisabled = false;

/** Tracks the current drone so stopAll() can fade it out. @type {{stop:function}|null} */
var _liveDroneHandle = null;


// --- initAudio ---------------------------------------------------------------

/**
 * initAudio()
 * Creates the AudioContext and master gain node on the first call after a user
 * gesture.  On subsequent calls it resumes a suspended context if one exists.
 * Safe to call multiple times.
 */
function initAudio() {
  // Resume a suspended context (e.g. after stopAll() / reset()).
  if (_audioContext && _audioContext.state === 'suspended') {
    _audioContext.resume().catch(function () {});
    return;
  }

  if (_audioContext || audioDisabled) return;

  try {
    var Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) { audioDisabled = true; return; }
    _audioContext = new Ctx();
    _masterGain = _audioContext.createGain();
    _masterGain.gain.value = 1;
    _masterGain.connect(_audioContext.destination);
  } catch (_) {
    audioDisabled = true;
  }
}


// --- playDrone ---------------------------------------------------------------

/**
 * playDrone(durationSeconds)
 * Plays a rising sub-bass rumble: two oscillators through a lowpass filter,
 * ramping from silence to 0.6 gain over durationSeconds.
 * Returns a handle with a stop() method for a graceful fade-out.
 *
 * @param {number} durationSeconds
 * @returns {{ stop: function }}
 */
function playDrone(durationSeconds) {
  if (audioDisabled || !_audioContext) return { stop: function () {} };

  var ctx = _audioContext;
  var now = ctx.currentTime;

  // Two oscillators for a muffled sub-bass rumble.
  var osc1 = ctx.createOscillator();
  osc1.type = 'sine';
  osc1.frequency.value = 40;

  var osc2 = ctx.createOscillator();
  osc2.type = 'sawtooth';
  osc2.frequency.value = 60;

  // Lowpass filter for muffled character.
  var filter = ctx.createBiquadFilter();
  filter.type = 'lowpass';
  filter.frequency.value = 200;
  filter.Q.value = 5;

  // Gain: ramp from 0 to 0.6 over durationSeconds.
  var gain = ctx.createGain();
  gain.gain.setValueAtTime(0, now);
  gain.gain.linearRampToValueAtTime(0.6, now + durationSeconds);

  osc1.connect(filter);
  osc2.connect(filter);
  filter.connect(gain);
  gain.connect(_masterGain);

  osc1.start(now);
  osc2.start(now);

  var handle = {
    stop: function () {
      var t = _audioContext ? _audioContext.currentTime : 0;
      gain.gain.setValueAtTime(gain.gain.value, t);
      gain.gain.linearRampToValueAtTime(0.0001, t + 0.3);
      setTimeout(function () {
        try { osc1.stop(); } catch (_) {}
        try { osc2.stop(); } catch (_) {}
        try { gain.disconnect(); } catch (_) {}
        try { filter.disconnect(); } catch (_) {}
      }, 350);
    }
  };

  _liveDroneHandle = handle;
  return handle;
}


// --- playSting ---------------------------------------------------------------

/**
 * playSting()
 * Fires a sharp, dissonant sting: three oscillators through a hard-clip wave
 * shaper, with a 5 ms attack and exponential decay to silence over 0.4 s.
 * Auto-stops all oscillators at 0.5 s.
 */
function playSting() {
  if (audioDisabled || !_audioContext) return;

  var ctx = _audioContext;
  var now = ctx.currentTime;

  // Three dissonant oscillators.
  var osc1 = ctx.createOscillator();
  osc1.type = 'sawtooth';
  osc1.frequency.value = 440;

  var osc2 = ctx.createOscillator();
  osc2.type = 'sawtooth';
  osc2.frequency.value = 466;

  var osc3 = ctx.createOscillator();
  osc3.type = 'square';
  osc3.frequency.value = 523;

  // Hard-clip distortion via wave shaper.
  var shaper = ctx.createWaveShaper();
  var curve = new Float32Array(256);
  for (var i = 0; i < 256; i++) {
    var x = (i * 2) / 255 - 1;
    curve[i] = Math.max(-0.8, Math.min(0.8, x * 3));
  }
  shaper.curve = curve;

  // Gain: 5 ms attack, exponential decay to 0.0001 over 0.4 s.
  var gain = ctx.createGain();
  gain.gain.setValueAtTime(0, now);
  gain.gain.linearRampToValueAtTime(0.8, now + 0.005);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.4);

  osc1.connect(shaper);
  osc2.connect(shaper);
  osc3.connect(shaper);
  shaper.connect(gain);
  gain.connect(_masterGain);

  osc1.start(now);
  osc2.start(now);
  osc3.start(now);

  // Auto-stop at 0.5 s.
  osc1.stop(now + 0.5);
  osc2.stop(now + 0.5);
  osc3.stop(now + 0.5);
}


// --- stopAll -----------------------------------------------------------------

/**
 * stopAll()
 * Fades out and stops the live drone, then suspends the AudioContext to silence
 * everything instantly.  Called by reset() in app.js.
 */
function stopAll() {
  if (_liveDroneHandle) {
    _liveDroneHandle.stop();
    _liveDroneHandle = null;
  }
  // Suspend the context to silence everything instantly.
  if (_audioContext && _audioContext.state === 'running') {
    _audioContext.suspend().catch(function () {});
  }
}


// --- setMute -----------------------------------------------------------------

/**
 * setMute(muted)
 * Silences or restores the master gain node.
 * No-op when _masterGain is not yet initialised.
 *
 * @param {boolean} muted
 */
function setMute(muted) {
  if (!_masterGain) return;
  _masterGain.gain.value = muted ? 0 : 1;
}
