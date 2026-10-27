// Network Intrusion Detection System endpoints.
//  * POST /api/nids/pcap         upload a .pcap/.pcapng -> C++ NIDS (rules + ML)
//  * live capture control         start/stop/status of the engine's libpcap capture
//  * POST /api/nids/ingest       alerts pushed by a stand-alone sensor
//                                (cyberguard_engine --sensor ...), key-authenticated
const Scan = require('../models/Scan');
const Threat = require('../models/Threat');
const engineClient = require('../services/engineClient');
const mitreMapping = require('../services/mitreMapping');

const SEV_RANK = { Safe: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const CATEGORY_MAP = { anomaly: 'network_anomaly', suspicious: 'network_anomaly' };
const storedLiveAlertKeys = new Set();

function actionsFor(alerts) {
  const types = new Set(alerts.map((a) => a.category));
  const actions = [];
  if (types.has('dos')) actions.push('Block suspicious IP/device', 'Notify administrator/SOC');
  if (types.has('probe')) actions.push('Block suspicious IP/device');
  if (types.has('r2l')) actions.push('Require additional authentication', 'Block suspicious IP/device');
  if (types.has('c2') || types.has('exfiltration')) actions.push('Escalate the incident for investigation', 'Revoke active session');
  if (!actions.length && alerts.length) actions.push('Notify administrator/SOC');
  if (!alerts.length) actions.push('No action required — continue monitoring');
  return [...new Set(actions)];
}

// One threat per alert category (highest severity wins), capped to keep the
// incident list readable during floods.
async function persistAlerts({ scan, alerts, userId }) {
  const byCat = new Map();
  for (const a of alerts) {
    if ((SEV_RANK[a.severity] || 0) < 2) continue;  // Medium+ become incidents
    const cat = CATEGORY_MAP[a.category] || a.category;
    const prev = byCat.get(cat);
    if (!prev || SEV_RANK[a.severity] > SEV_RANK[prev.severity]) byCat.set(cat, a);
  }
  const created = [];
  for (const [category, a] of [...byCat.entries()].slice(0, 12)) {
    const riskLevel = a.severity === 'Safe' ? 'Low' : a.severity;
    const t = await Threat.create({
      scanId: scan.id, category, riskLevel, targetUserId: userId || null,
      targetedService: String(a.dst).slice(0, 250),
      recommendedAction: `${a.type}: ${a.evidence}`.slice(0, 1000), status: 'open',
    });
    created.push({ threatId: t.id, category, riskLevel, type: a.type });
  }
  return created;
}

async function uploadPcap(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: 'capture file is required (field name "capture", .pcap or .pcapng)' });
    const result = await engineClient.analyzePcap(req.file.buffer, req.file.originalname);
    if (result.error) return res.status(400).json({ error: result.error });
    const recommendedActions = actionsFor(result.alerts || []);
    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'network_pcap',
      inputSummary: `${req.file.originalname}: ${result.summary.packets} packets, ${result.summary.connections} connections`,
      engineResult: { summary: result.summary, alerts: result.alerts, flows: (result.flows || []).slice(0, 60) },
      mlResult: { available: result.mlAvailable, flagged: result.summary.mlFlaggedConnections, novel: result.summary.novelConnections, byCategory: result.summary.mlByCategory },
      finalScore: result.score,
      riskLevel: result.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });
    const threatsCreated = await persistAlerts({ scan, alerts: result.alerts || [], userId: req.user?.id });
    res.json({
      scanId: scan.id,
      ...result,
      recommendedActions,
      threatsCreated,
      mitreAttack: [...new Set((result.alerts || []).map((a) => CATEGORY_MAP[a.category] || a.category))]
        .map((c) => ({ category: c, techniques: mitreMapping.techniquesForCategory(c) })),
    });
  } catch (err) {
    const detail = err.response?.data?.error || err.message;
    res.status(500).json({ error: 'Capture analysis failed', detail });
  }
}

async function interfaces(req, res) {
  try { res.json(await engineClient.nidsInterfaces()); } catch (e) { res.status(502).json({ error: 'Engine unreachable', detail: e.message }); }
}

async function liveStart(req, res) {
  try {
    const { iface, bpf, windowSeconds } = req.body || {};
    res.json(await engineClient.nidsLiveStart({ iface, bpf, windowSeconds }));
  } catch (e) { res.status(502).json({ error: 'Engine unreachable', detail: e.message }); }
}

async function liveStop(req, res) {
  try { res.json(await engineClient.nidsLiveStop()); } catch (e) { res.status(502).json({ error: 'Engine unreachable', detail: e.message }); }
}

// Polling the status also persists alerts that have not been stored yet.
async function liveStatus(req, res) {
  try {
    const status = await engineClient.nidsLiveStatus();
    const fresh = (status.alerts || []).filter((a) => {
      const key = `${a.type}|${a.src}|${a.dst}|${a.detectedAt}`;
      if (storedLiveAlertKeys.has(key)) return false;
      storedLiveAlertKeys.add(key);
      return true;
    });
    if (fresh.length) {
      const worst = fresh.reduce((w, a) => (SEV_RANK[a.severity] > SEV_RANK[w] ? a.severity : w), 'Safe');
      const scan = await Scan.create({
        userId: req.user?.id || null, scanType: 'network_live', source: 'live_capture',
        inputSummary: `Live capture on ${status.iface}: ${fresh.length} new alert(s)`,
        engineResult: { alerts: fresh, summary: status.lastAnalysis?.summary || null },
        finalScore: { Safe: 0, Low: 20, Medium: 45, High: 75, Critical: 95 }[worst] || 0, riskLevel: worst,
        recommendedAction: actionsFor(fresh).join('; '),
      });
      await persistAlerts({ scan, alerts: fresh, userId: req.user?.id });
    }
    res.json(status);
  } catch (e) { res.status(502).json({ error: 'Engine unreachable', detail: e.message }); }
}

// Sensor push (cyberguard_engine --sensor --report http://backend:4000/api/nids/ingest --key <ENGINE_KEY>)
async function ingest(req, res) {
  const expected = process.env.SENSOR_KEY || process.env.ENGINE_KEY || '';
  if (!expected || req.headers['x-engine-key'] !== expected) {
    return res.status(401).json({ error: 'invalid or missing sensor key (set ENGINE_KEY or SENSOR_KEY and pass it with --key)' });
  }
  try {
    const { sensor, iface, alerts = [], summary, riskLevel, score } = req.body || {};
    const scan = await Scan.create({
      userId: null, scanType: 'network_live', source: 'nids_sensor',
      inputSummary: `Sensor ${sensor || 'unknown'} (${iface || '?'}): ${alerts.length} new alert(s)`,
      engineResult: { alerts, summary, sensor, iface },
      finalScore: score || 0, riskLevel: riskLevel || 'Safe',
      recommendedAction: actionsFor(alerts).join('; '),
    });
    const threatsCreated = await persistAlerts({ scan, alerts, userId: null });
    res.json({ stored: true, scanId: scan.id, threatsCreated: threatsCreated.length });
  } catch (e) {
    res.status(500).json({ error: 'ingest failed', detail: e.message });
  }
}

async function events(req, res) {
  const { Op } = require('sequelize');
  const where = { scanType: { [Op.in]: ['network_pcap', 'network_live'] } };
  if (req.user.role !== 'admin') where[Op.or] = [{ userId: req.user.id }, { source: 'nids_sensor' }];
  const scans = await Scan.findAll({ where, order: [['createdAt', 'DESC']], limit: 50 });
  res.json({
    events: scans.map((s) => ({
      id: s.id, scanType: s.scanType, source: s.source, summary: s.inputSummary, riskLevel: s.riskLevel,
      score: s.finalScore, createdAt: s.createdAt, alerts: (s.engineResult?.alerts || []).slice(0, 20),
    })),
  });
}

module.exports = { uploadPcap, interfaces, liveStart, liveStop, liveStatus, ingest, events };
