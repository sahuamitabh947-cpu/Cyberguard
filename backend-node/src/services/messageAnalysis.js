// Shared phishing analysis pipeline for any message: the manual
// "Message / Email" scan and the Gmail inbox scanner both use this, so a
// message gets exactly the same treatment wherever it comes from.
//
//   C++ rule engine  +  C++ ML model (TF-IDF + Logistic Regression)
//   + embedded-link analysis (static + URL ML, optional live deep check)
//   + sender-authentication findings (Gmail: SPF/DKIM/DMARC, reply-to...)
//   + optional Gemini classification / explanation
//   -> fused Safe..Critical score with explanation and response actions.
const engineClient = require('./engineClient');
const geminiService = require('./geminiService');
const liveUrlService = require('./liveUrlService');

const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"')\]]+)/gi;

function extractLinks(text, extra = []) {
  const found = new Set(extra.filter(Boolean));
  for (const m of (text || '').matchAll(URL_RE)) found.add(m[1].replace(/[.,;:!?]+$/, ''));
  return [...found].slice(0, 25);
}

function mlComponent(ml, weight, source = 'ml_model') {
  if (!ml || !ml.available) return null;
  return { source, score: ml.score, weight };
}

function fallbackActions(riskLevel) {
  if (riskLevel === 'Safe' || riskLevel === 'Low') return ['No action required — continue monitoring'];
  return ['Quarantine email', 'Warn the user', 'Block suspicious URL'];
}

/**
 * @param {object} p
 * @param {string} p.text              message body (plain text)
 * @param {string} [p.claimedSender]
 * @param {string[]} [p.links]         links found in HTML parts (Gmail)
 * @param {object[]} [p.extraFindings] e.g. header-authentication findings
 * @param {number} [p.extraScore]      score of those findings (0-100)
 * @param {boolean} [p.liveLinks]      run the live deep check on the top link(s)
 * @param {boolean} [p.useGemini]
 */
async function analyzeMessage(p) {
  const text = p.text || '';
  const ruleResult = await engineClient.analyzeText(text, p.claimedSender || '');
  const ml = ruleResult.ml || { available: false };

  // Embedded links: static rule engine + URL ML (fast), live check optional.
  const links = extractLinks(text, p.links || []);
  const linkResults = [];
  for (const link of links.slice(0, 8)) {
    try {
      const r = await engineClient.analyzeUrl(link);
      linkResults.push({ url: link, host: r.host, registrableDomain: r.anatomy?.registrableDomain, riskLevel: r.riskLevel, score: r.score,
        mlProbability: r.ml?.available ? r.ml.probability : null, findings: (r.findings || []).filter((f) => f.weight > 0).slice(0, 4) });
    } catch (e) { /* engine hiccup on one link: skip it */ }
  }
  linkResults.sort((a, b) => Math.max(b.score, (b.mlProbability || 0) * 100) - Math.max(a.score, (a.mlProbability || 0) * 100));
  if (p.liveLinks && linkResults.length && require('./systemMode').isOnline()) {
    const top = linkResults.slice(0, 2);
    await Promise.all(top.map(async (lr) => {
      try {
        const live = await Promise.race([liveUrlService.liveCheck(lr.url), new Promise((r) => setTimeout(() => r(null), 15000))]);
        if (live) { lr.live = { reachable: live.reachable, finalUrl: live.finalUrl, score: live.score, findings: live.findings.filter((f) => f.weight > 0) }; }
      } catch (e) { /* ignore */ }
    }));
  }

  let aiResult = null;
  if (p.useGemini !== false && geminiService.isConfigured()) {
    try { aiResult = await geminiService.classifyPhishingText(text.slice(0, 12000), p.claimedSender, ruleResult.findings); } catch (e) {
      console.warn('[message] Gemini call failed:', e.message);
    }
  }

  const components = [{ source: 'rule_engine', score: ruleResult.score, weight: 0.6 }];
  const mlc = mlComponent(ml, 0.9, 'ml_text_model');
  if (mlc) components.push(mlc);
  if (aiResult && !aiResult.error) components.push({ source: 'gemini_ai', score: aiResult.confidenceScore, weight: 1.0 });
  const worstLink = linkResults[0];
  if (worstLink) {
    const linkScore = Math.max(worstLink.score, worstLink.live ? worstLink.live.score : 0, Math.round((worstLink.mlProbability || 0) * 100 * 0.8));
    components.push({ source: 'embedded_links', score: linkScore, weight: 0.8 });
  }
  if (p.extraFindings && p.extraFindings.length) components.push({ source: 'sender_authentication', score: Math.min(100, p.extraScore || 0), weight: 0.8 });

  const combinedFindings = [
    ...ruleResult.findings,
    ...(p.extraFindings || []),
    ...((aiResult?.additionalIndicators || []).map((i) => ({ indicator: 'ai_indicator', detail: i, weight: 10 }))),
  ];
  if (ml.available && ml.probability >= 0.5) {
    const terms = (ml.topIndicativeTerms || []).map((t) => `"${t.term}"`).slice(0, 5).join(', ');
    combinedFindings.push({ indicator: 'ml_text_classifier', detail: `C++ ML model (TF-IDF + Logistic Regression) rates this message ${Math.round(ml.probability * 100)}% likely phishing/scam${terms ? `; strongest signals: ${terms}` : ''}`, weight: Math.round(ml.score / 4) });
  }
  if (worstLink && (worstLink.score >= 30 || (worstLink.mlProbability || 0) >= 0.5 || (worstLink.live && worstLink.live.score >= 30))) {
    const why = [...(worstLink.findings || []), ...((worstLink.live && worstLink.live.findings) || [])].map((f) => f.detail).slice(0, 2).join('; ');
    combinedFindings.push({ indicator: 'malicious_link_in_message', detail: `Embedded link ${worstLink.url.slice(0, 80)} is ${worstLink.riskLevel}${worstLink.mlProbability !== null ? ` (URL ML ${Math.round(worstLink.mlProbability * 100)}%)` : ''}${why ? `: ${why}` : ''}`, weight: 20 });
  }
  const fused = await engineClient.fuse(components, combinedFindings);

  let explanation = null;
  if (p.useGemini !== false && geminiService.isConfigured()) {
    try {
      explanation = await geminiService.generateExplanation({ category: 'phishing', riskLevel: fused.riskLevel, score: fused.finalScore, findings: combinedFindings });
    } catch (e) { /* non-fatal */ }
  }
  return {
    ruleResult, ml, aiResult, fused, combinedFindings, linkResults, components,
    explanation: explanation?.explanation || null,
    recommendedActions: explanation?.recommendedActions || fallbackActions(fused.riskLevel),
  };
}

module.exports = { analyzeMessage, extractLinks, mlComponent };
