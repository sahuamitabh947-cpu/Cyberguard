// Online / offline operating mode.
//
// CYBERGUARD_MODE = online | offline | auto   (default: auto)
//   online  - internet features always allowed (Gemini, Gmail, live URL checks)
//   offline - never contacts the internet; rules + C++ ML models still run fully
//   auto    - probes connectivity in the background and switches automatically
//
// The probe never blocks a request: isOnline() only reads a cached value that a
// timer refreshes, so scans are never slowed down by the check itself.
const dns = require('dns').promises;
const https = require('https');

const RAW = String(process.env.CYBERGUARD_MODE || 'auto').toLowerCase();
const MODE = ['online', 'offline', 'auto'].includes(RAW) ? RAW : 'auto';
const PROBE_EVERY_MS = Math.max(15000, Number(process.env.CYBERGUARD_PROBE_INTERVAL_MS) || 60000);
const PROBE_HOST = process.env.CYBERGUARD_PROBE_HOST || 'www.google.com';

let reachable = MODE !== 'offline';      // optimistic until the first probe finishes
let lastProbeAt = null;
let timer = null;

function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
}

function httpsHead(host) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host, path: '/generate_204', method: 'HEAD', timeout: 4000 }, (res) => { res.resume(); resolve(res.statusCode); });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function probe() {
  try {
    await withTimeout(dns.lookup(PROBE_HOST), 3000);
    await withTimeout(httpsHead(PROBE_HOST), 5000);
    reachable = true;
  } catch (e) {
    reachable = false;
  }
  lastProbeAt = new Date();
  return reachable;
}

function start() {
  if (MODE !== 'auto' || timer) return;
  probe().catch(() => {});
  timer = setInterval(() => { probe().catch(() => {}); }, PROBE_EVERY_MS);
  if (timer.unref) timer.unref();
}

function isOnline() {
  if (MODE === 'offline') return false;
  if (MODE === 'online') return true;
  return reachable;
}

function effective() { return isOnline() ? 'online' : 'offline'; }

function status() {
  const online = isOnline();
  const why = MODE === 'offline' ? 'Offline mode is switched on' : 'No internet connection';
  const feat = (available, needsKey, keyMissingReason) => {
    if (!online) return { available: false, reason: why };
    if (needsKey) return { available: false, reason: keyMissingReason };
    return { available: true, reason: null };
  };
  return {
    mode: MODE,
    effective: effective(),
    online,
    lastProbeAt,
    features: {
      coreDetection: { available: true, reason: null },
      gemini: feat(true, !process.env.GEMINI_API_KEY, 'Gemini API key not configured'),
      gmail: feat(true, !(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET), 'Google sign-in not configured'),
      liveUrlCheck: feat(true, false),
    },
  };
}

// Express middleware: block a route while offline with a clear, non-crashing error.
function requireOnline(featureName) {
  return (req, res, next) => {
    if (isOnline()) return next();
    return res.status(503).json({ error: `${featureName} needs an internet connection. CyberGuard is running in offline mode.`, code: 'OFFLINE_MODE' });
  };
}

module.exports = { start, probe, isOnline, effective, status, requireOnline, MODE };
