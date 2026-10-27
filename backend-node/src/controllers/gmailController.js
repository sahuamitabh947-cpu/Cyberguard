// "Connect Gmail" feature: scans the user's inbox for phishing with the same
// pipeline as the manual Message/Email scan, plus sender-authentication checks.
const { Op } = require('sequelize');
const GmailConnection = require('../models/GmailConnection');
const Scan = require('../models/Scan');
const gmail = require('../services/gmailService');
const { analyzeMessage } = require('../services/messageAnalysis');
const { createThreatIfNeeded } = require('./scanController');

const FRONTEND = () => process.env.FRONTEND_URL || 'http://localhost:3000';

async function status(req, res) {
  const conn = await GmailConnection.findOne({ where: { userId: req.user.id } });
  res.json({
    configured: gmail.isConfigured(),
    redirectUri: gmail.redirectUri(),
    connected: Boolean(conn),
    gmailAddress: conn?.gmailAddress || null,
    connectedAt: conn?.connectedAt || null,
    lastSyncAt: conn?.lastSyncAt || null,
    messagesScanned: conn?.messagesScanned || 0,
  });
}

async function connect(req, res) {
  if (!gmail.isConfigured()) {
    return res.status(503).json({ error: 'Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env and enable the Gmail API (see README > Gmail).' });
  }
  res.json({ url: gmail.authUrl(req.user.id) });
}

async function callback(req, res) {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${FRONTEND()}/gmail?error=${encodeURIComponent(error)}`);
  try {
    const userId = gmail.verifyState(state);
    const tokens = await gmail.exchangeCode(code);
    if (!tokens.refresh_token) {
      return res.redirect(`${FRONTEND()}/gmail?error=${encodeURIComponent('Google did not return a refresh token. Remove CyberGuard from https://myaccount.google.com/permissions and connect again.')}`);
    }
    let address = null;
    try { address = (await gmail.profile(tokens.access_token)).emailAddress; } catch (e) { /* optional */ }
    const values = { userId, gmailAddress: address, refreshTokenEnc: gmail.encrypt(tokens.refresh_token), scopes: tokens.scope || '', connectedAt: new Date() };
    const existing = await GmailConnection.findOne({ where: { userId } });
    if (existing) await existing.update(values); else await GmailConnection.create(values);
    res.redirect(`${FRONTEND()}/gmail?connected=1`);
  } catch (e) {
    const msg = e.response?.data?.error_description || e.message;
    res.redirect(`${FRONTEND()}/gmail?error=${encodeURIComponent(`Gmail connection failed: ${msg}`)}`);
  }
}

async function disconnect(req, res) {
  const conn = await GmailConnection.findOne({ where: { userId: req.user.id } });
  if (conn) {
    if (require('../services/systemMode').isOnline()) {
      try { await gmail.revoke(gmail.decrypt(conn.refreshTokenEnc)); } catch (e) { /* ignore */ }
    }
    await conn.destroy();
  }
  res.json({ disconnected: true });
}

function summarise(scan) {
  const e = scan.engineResult?.email || {};
  return {
    scanId: scan.id, gmailId: scan.externalRef, from: e.from, subject: e.subject, date: e.date, snippet: e.snippet,
    auth: e.auth, attachments: e.attachments || [], riskLevel: scan.riskLevel, score: scan.finalScore,
    mlProbability: scan.mlResult?.available ? scan.mlResult.probability : null,
    findings: (scan.engineResult?.findings || []).filter((f) => f.weight > 0).slice(0, 8),
    links: (scan.engineResult?.links || []).slice(0, 5),
    explanation: scan.engineResult?.explanation || null,
    recommendedAction: scan.recommendedAction, scannedAt: scan.createdAt,
  };
}

async function scanInbox(req, res) {
  const conn = await GmailConnection.findOne({ where: { userId: req.user.id } });
  if (!conn) return res.status(400).json({ error: 'Gmail is not connected' });
  const max = Math.min(parseInt(req.body?.max, 10) || 25, 100);
  const query = req.body?.query || 'in:inbox newer_than:30d';
  const useAi = Boolean(req.body?.useAi);
  try {
    const token = await gmail.accessToken(gmail.decrypt(conn.refreshTokenEnc));
    const ids = await gmail.listMessageIds(token, { max, query });
    const already = new Set((await Scan.findAll({
      where: { userId: req.user.id, source: 'gmail', externalRef: { [Op.in]: ids.length ? ids : ['-'] } }, attributes: ['externalRef'],
    })).map((s) => s.externalRef));
    let scanned = 0;
    let flagged = 0;
    const results = [];
    for (const id of ids) {
      if (already.has(id)) continue;
      const msg = gmail.parseMessage(await gmail.getMessage(token, id));
      const sender = gmail.senderChecks(msg);
      const body = `Subject: ${msg.subject}\n\n${msg.text}`;
      const a = await analyzeMessage({
        text: body, claimedSender: msg.from.email, links: msg.links, extraFindings: sender.findings, extraScore: sender.score,
        liveLinks: false, useGemini: useAi,
      });
      const scan = await Scan.create({
        userId: req.user.id, scanType: 'email', source: 'gmail', externalRef: id,
        inputSummary: `From: ${msg.from.name ? `${msg.from.name} <${msg.from.email}>` : msg.from.email} | ${msg.subject}`.slice(0, 300),
        engineResult: {
          email: { from: msg.from, replyTo: msg.replyTo, subject: msg.subject, date: msg.date, snippet: msg.snippet, auth: msg.auth, attachments: msg.attachments },
          rule: a.ruleResult, findings: a.combinedFindings, links: a.linkResults, explanation: a.explanation,
        },
        aiResult: a.aiResult, mlResult: a.ml,
        finalScore: a.fused.finalScore, riskLevel: a.fused.riskLevel, recommendedAction: a.recommendedActions.join('; '),
      });
      await createThreatIfNeeded({ scan, category: 'phishing' });
      scanned++;
      if (!['Safe', 'Low'].includes(a.fused.riskLevel)) flagged++;
      results.push(summarise(scan));
    }
    await conn.update({ lastSyncAt: new Date(), messagesScanned: (conn.messagesScanned || 0) + scanned });
    res.json({ fetched: ids.length, scanned, skippedAlreadyScanned: ids.length - scanned, flagged, results });
  } catch (e) {
    const status = e.response?.status;
    const detail = e.response?.data?.error?.message || e.response?.data?.error_description || e.message;
    if (status === 401 || status === 400) {
      // 409 (not 401): a 401 would make the web app log the CyberGuard user out.
      return res.status(409).json({ error: 'Gmail access expired or was revoked - please reconnect Gmail.', code: 'GMAIL_REAUTH', detail });
    }
    if (status === 403) {
      return res.status(403).json({ error: 'Gmail API refused the request. Make sure the Gmail API is enabled for your Google Cloud project and your account is a test user on the OAuth consent screen.', detail });
    }
    res.status(500).json({ error: 'Inbox scan failed', detail });
  }
}

async function messages(req, res) {
  const filter = req.query.filter || 'all';
  const where = { userId: req.user.id, source: 'gmail' };
  if (filter === 'phishing') where.riskLevel = { [Op.in]: ['Medium', 'High', 'Critical'] };
  const scans = await Scan.findAll({ where, order: [['createdAt', 'DESC']], limit: Math.min(parseInt(req.query.limit, 10) || 100, 300) });
  res.json({ messages: scans.map(summarise) });
}

module.exports = { status, connect, callback, disconnect, scanInbox, messages };
