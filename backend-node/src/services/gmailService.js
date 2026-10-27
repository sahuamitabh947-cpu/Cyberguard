// Gmail integration (read-only).
//
// OAuth 2.0 with the gmail.readonly scope: CyberGuard can read messages to
// scan them but can never send, delete or modify mail. The refresh token is
// stored AES-256-GCM encrypted. Base URLs are overridable for testing
// against a local mock (GOOGLE_OAUTH_TOKEN_URL, GMAIL_API_BASE).
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../middleware/authMiddleware');
const { getDomain } = require('tldts');

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = () => process.env.GOOGLE_OAUTH_TOKEN_URL || 'https://oauth2.googleapis.com/token';
const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
const API = () => process.env.GMAIL_API_BASE || 'https://gmail.googleapis.com/gmail/v1';
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'openid', 'email'];

function isConfigured() {
  return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
}
function redirectUri() {
  return process.env.GMAIL_REDIRECT_URI || 'http://localhost:4000/api/gmail/callback';
}

// ------------------------------------------------------------ crypto --
function key() {
  return crypto.createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY || JWT_SECRET).digest();
}
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [iv.toString('base64'), c.getAuthTag().toString('base64'), enc.toString('base64')].join('.');
}
function decrypt(blob) {
  const [iv, tag, enc] = blob.split('.').map((p) => Buffer.from(p, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', key(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

// ------------------------------------------------------------- OAuth --
function authUrl(userId) {
  const state = jwt.sign({ uid: userId, purpose: 'gmail-connect' }, JWT_SECRET, { expiresIn: '10m' });
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: redirectUri(), response_type: 'code',
    scope: SCOPES.join(' '), access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state,
  });
  return `${AUTH_URL}?${params}`;
}
function verifyState(state) {
  const p = jwt.verify(state, JWT_SECRET);
  if (p.purpose !== 'gmail-connect') throw new Error('bad state');
  return p.uid;
}
async function exchangeCode(code) {
  const { data } = await axios.post(TOKEN_URL(), new URLSearchParams({
    code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: redirectUri(), grant_type: 'authorization_code',
  }), { timeout: 10000 });
  return data;
}
async function accessToken(refreshToken) {
  const { data } = await axios.post(TOKEN_URL(), new URLSearchParams({
    refresh_token: refreshToken, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
    grant_type: 'refresh_token',
  }), { timeout: 10000 });
  return data.access_token;
}
async function revoke(refreshToken) {
  try { await axios.post(`${REVOKE_URL}?token=${encodeURIComponent(refreshToken)}`, null, { timeout: 8000 }); } catch (e) { /* best effort */ }
}

// ------------------------------------------------------------- Gmail --
async function gmailGet(token, path, params) {
  const { data } = await axios.get(`${API()}${path}`, { headers: { Authorization: `Bearer ${token}` }, params, timeout: 15000 });
  return data;
}
async function profile(token) {
  return gmailGet(token, '/users/me/profile');
}
async function listMessageIds(token, { max = 25, query = 'in:inbox newer_than:30d' } = {}) {
  const data = await gmailGet(token, '/users/me/messages', { maxResults: Math.min(max, 100), q: query });
  return (data.messages || []).map((m) => m.id);
}
async function getMessage(token, id) {
  return gmailGet(token, `/users/me/messages/${id}`, { format: 'full' });
}

// ------------------------------------------------------------ parsing --
function b64url(s) {
  return Buffer.from((s || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function htmlToText(html) {
  return html.replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}
function parseAddress(v) {
  if (!v) return { name: '', email: '' };
  const m = v.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>/);
  if (m) return { name: m[1].trim(), email: m[2].trim().toLowerCase() };
  return { name: '', email: v.trim().toLowerCase() };
}
function domainOf(email) {
  const d = (email || '').split('@')[1] || '';
  return getDomain(d, { allowPrivateDomains: false }) || d;
}

function parseMessage(msg) {
  const headers = {};
  for (const h of msg.payload?.headers || []) {
    const k = h.name.toLowerCase();
    headers[k] = headers[k] ? `${headers[k]}\n${h.value}` : h.value;
  }
  let text = '';
  let html = '';
  const attachments = [];
  const walk = (part) => {
    if (!part) return;
    if (part.filename) attachments.push({ filename: part.filename, mimeType: part.mimeType, size: part.body?.size || 0 });
    else if (part.mimeType === 'text/plain' && part.body?.data) text += `${b64url(part.body.data)}\n`;
    else if (part.mimeType === 'text/html' && part.body?.data) html += b64url(part.body.data);
    (part.parts || []).forEach(walk);
  };
  walk(msg.payload);
  const hrefs = [...html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]).filter((h) => /^https?:/i.test(h));
  // Link text vs real target mismatch (e.g. text shows paypal.com, href goes elsewhere)
  const deceptiveLinks = [];
  for (const m of html.matchAll(/<a[^>]*href\s*=\s*["'](https?:[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const shown = htmlToText(m[2]);
    const shownUrl = shown.match(/(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
    if (shownUrl) {
      try {
        const realReg = getDomain(new URL(m[1]).hostname, { allowPrivateDomains: true });
        const shownReg = getDomain(shownUrl[1], { allowPrivateDomains: true });
        if (realReg && shownReg && realReg !== shownReg) deceptiveLinks.push({ shown: shownUrl[1], actual: new URL(m[1]).hostname });
      } catch (e) { /* ignore */ }
    }
  }
  if (!text.trim() && html) text = htmlToText(html);
  const auth = (headers['authentication-results'] || '').toLowerCase();
  const pick = (proto) => {
    const m = auth.match(new RegExp(`${proto}=(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)`));
    return m ? m[1] : 'none';
  };
  const from = parseAddress(headers.from);
  return {
    id: msg.id, threadId: msg.threadId, labelIds: msg.labelIds || [], snippet: msg.snippet || '',
    subject: headers.subject || '(no subject)', date: headers.date || null,
    from, replyTo: parseAddress(headers['reply-to']), returnPath: parseAddress(headers['return-path']),
    auth: { spf: pick('spf'), dkim: pick('dkim'), dmarc: pick('dmarc'), raw: (headers['authentication-results'] || '').slice(0, 1000) },
    text: text.slice(0, 20000), links: [...new Set(hrefs)].slice(0, 40), deceptiveLinks: deceptiveLinks.slice(0, 5), attachments,
  };
}

const FREE_MAIL = new Set(['gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com', 'live.com', 'aol.com', 'proton.me', 'protonmail.com', 'icloud.com', 'rediffmail.com', 'zoho.com', 'gmx.com', 'mail.com']);
const BRANDS = {
  paypal: ['paypal.com'], amazon: ['amazon.com', 'amazon.in', 'amazonses.com'], microsoft: ['microsoft.com', 'outlook.com', 'office.com', 'live.com'],
  google: ['google.com', 'gmail.com', 'youtube.com'], apple: ['apple.com', 'icloud.com'], netflix: ['netflix.com'], facebook: ['facebook.com', 'facebookmail.com', 'meta.com'],
  instagram: ['instagram.com', 'facebookmail.com'], linkedin: ['linkedin.com'], sbi: ['sbi.co.in', 'onlinesbi.sbi'], hdfc: ['hdfcbank.com', 'hdfcbank.net'],
  icici: ['icicibank.com'], axis: ['axisbank.com'], irctc: ['irctc.co.in'], 'income tax': ['incometax.gov.in'], uidai: ['uidai.gov.in'], paytm: ['paytm.com'],
  phonepe: ['phonepe.com'], flipkart: ['flipkart.com'], dhl: ['dhl.com'], fedex: ['fedex.com'], docusign: ['docusign.com', 'docusign.net'], dropbox: ['dropbox.com'],
  whatsapp: ['whatsapp.com'], github: ['github.com'],
};
const RISKY_ATTACH = /\.(exe|scr|js|jse|vbs|vbe|wsf|hta|html?|shtml|svg|iso|img|lnk|bat|cmd|ps1|msi|jar|docm|xlsm|pptm|one|zip|rar|7z)$/i;

// Sender-authenticity analysis (PRD innovation item: "email sender authenticity analysis").
function senderChecks(p) {
  const findings = [];
  let score = 0;
  const add = (indicator, detail, weight) => { findings.push({ indicator, detail, weight }); score += weight; };
  const fromDom = domainOf(p.from.email);
  if (p.auth.dmarc === 'fail') add('dmarc_fail', `DMARC failed: the message is not authorised by ${fromDom}, even though it claims to be from it`, 35);
  if (['fail', 'softfail'].includes(p.auth.spf)) add('spf_fail', `SPF ${p.auth.spf}: the sending server is not allowed to send mail for ${fromDom}`, 20);
  if (p.auth.dkim === 'fail') add('dkim_fail', 'DKIM signature failed: the message may have been altered or forged', 15);
  if (p.auth.spf === 'none' && p.auth.dkim === 'none' && p.auth.dmarc === 'none') add('no_sender_authentication', 'No SPF/DKIM/DMARC authentication result for this sender', 8);
  if (p.replyTo.email && domainOf(p.replyTo.email) !== fromDom)
    add('reply_to_mismatch', `Replies go to ${p.replyTo.email}, a different domain from the sender (${p.from.email})`, 20);
  const name = (p.from.name || '').toLowerCase();
  const nameEmail = name.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/);
  if (nameEmail && nameEmail[0] !== p.from.email) add('display_name_address_spoof', `Display name shows "${nameEmail[0]}" but the real sender is ${p.from.email}`, 30);
  for (const [brand, domains] of Object.entries(BRANDS)) {
    if (name.includes(brand) && !domains.includes(fromDom)) {
      add('display_name_brand_spoof', `Sender name says "${p.from.name}" but the address is ${p.from.email}, which is not an official ${brand} domain`, 30);
      break;
    }
  }
  if (FREE_MAIL.has(fromDom) && /(support|team|security|bank|service|helpdesk|admin|official|department|verification|billing)/i.test(p.from.name))
    add('free_mailbox_impersonating_org', `"${p.from.name}" claims to be an organisation but writes from a free ${fromDom} mailbox`, 15);
  for (const d of p.deceptiveLinks) add('deceptive_link_text', `Link text shows "${d.shown}" but actually opens ${d.actual}`, 25);
  const risky = p.attachments.filter((a) => RISKY_ATTACH.test(a.filename));
  if (risky.length) add('risky_attachment', `Risky attachment type: ${risky.map((a) => a.filename).join(', ')}`, 25);
  return { findings, score: Math.min(100, score) };
}

module.exports = {
  isConfigured, authUrl, verifyState, exchangeCode, accessToken, revoke, profile, listMessageIds, getMessage,
  parseMessage, senderChecks, encrypt, decrypt, redirectUri, SCOPES,
};
