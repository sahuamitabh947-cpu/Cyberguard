const { Op } = require('sequelize');
const sequelize = require('../config/db');
const Scan = require('../models/Scan');
const systemMode = require('../services/systemMode');
const Threat = require('../models/Threat');
const engineClient = require('../services/engineClient');
const geminiService = require('../services/geminiService');
const qrService = require('../services/qrService');
const liveUrlService = require('../services/liveUrlService');
const videoService = require('../services/videoService');
const mitreMapping = require('../services/mitreMapping');
const { analyzeMessage, mlComponent } = require('../services/messageAnalysis');

function recommendFallbackActions(category, riskLevel) {
  if (riskLevel === 'Safe' || riskLevel === 'Low') return ['No action required — continue monitoring'];
  const map = {
    phishing: ['Quarantine email', 'Warn the user', 'Block suspicious URL'],
    malicious_url: ['Block suspicious URL', 'Warn the user'],
    impersonation: ['Report impersonation', 'Notify administrator/SOC'],
    deepfake: ['Flag multimedia for manual verification', 'Notify administrator/SOC'],
    account_takeover: ['Revoke active session', 'Require additional authentication', 'Block suspicious IP/device'],
    network_threat: ['Block suspicious IP/device', 'Notify administrator/SOC'],
    api_abuse: ['Block suspicious IP/device', 'Require additional authentication'],
    data_exfiltration: ['Revoke active session', 'Escalate the incident for investigation'],
    insider_threat: ['Escalate the incident for investigation', 'Notify administrator/SOC'],
    malware: ['Flag multimedia for manual verification', 'Escalate the incident for investigation'],
    technical_threat: ['Notify administrator/SOC', 'Escalate the incident for investigation'],
  };
  return map[category] || ['Notify administrator/SOC'];
}

async function createThreatIfNeeded({ scan, category }) {
  if (scan.riskLevel === 'Safe' || scan.riskLevel === 'Low') return null;
  return Threat.create({
    scanId: scan.id,
    category,
    riskLevel: scan.riskLevel,
    targetUserId: scan.userId,
    recommendedAction: scan.recommendedAction,
    status: 'open',
  });
}

function withMitre(payload, category) {
  return { ...payload, mitreAttack: mitreMapping.techniquesForCategory(category) };
}

function mlFinding(ml, indicator, label) {
  if (!ml || !ml.available || ml.probability < 0.5) return null;
  const why = (ml.topFeatures || ml.topIndicativeTerms || []).slice(0, 4)
    .map((t) => (t.term ? `"${t.term}"` : t.feature)).join(', ');
  return { indicator, detail: `${label} rates this ${Math.round(ml.probability * 100)}% likely malicious${why ? ` (driven by: ${why})` : ''}`, weight: Math.round(ml.score / 4) };
}

// ---------- Phishing: email / SMS / message text (manual paste) ----------
async function scanText(req, res) {
  try {
    const { text, claimedSender, channel } = req.body; // channel: 'email' | 'sms'
    if (!text) return res.status(400).json({ error: 'text is required' });

    const a = await analyzeMessage({ text, claimedSender, liveLinks: true });
    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: channel === 'sms' ? 'sms' : 'email',
      inputSummary: text.slice(0, 300),
      engineResult: a.ruleResult,
      aiResult: a.aiResult,
      mlResult: a.ml,
      finalScore: a.fused.finalScore,
      riskLevel: a.fused.riskLevel,
      recommendedAction: a.recommendedActions.join('; '),
    });
    const threat = await createThreatIfNeeded({ scan, category: 'phishing' });

    res.json(withMitre({
      scanId: scan.id,
      riskLevel: a.fused.riskLevel,
      score: a.fused.finalScore,
      findings: a.combinedFindings,
      aiExplanation: a.explanation,
      recommendedActions: a.recommendedActions,
      threatCreated: Boolean(threat),
      ml: a.ml,
      links: a.linkResults,
      scoreComponents: a.components,
    }, 'phishing'));
  } catch (err) {
    res.status(500).json({ error: 'Text scan failed', detail: err.message });
  }
}

// ---------- Malicious URL / website detection (static + ML + deep live checks) ----------
async function scanUrl(req, res) {
  try {
    const { url, skipLiveCheck } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required' });

    const ruleResult = await engineClient.analyzeUrl(url);
    const ml = ruleResult.ml || { available: false };
    const components = [{ source: 'rule_engine', score: ruleResult.score, weight: 1.0 }];
    const mlc = mlComponent(ml, 0.9, 'ml_url_model');
    if (mlc) components.push(mlc);
    let liveResult = null;
    let destination = null;

    if (!skipLiveCheck && systemMode.isOnline()) {
      try {
        liveResult = await liveUrlService.liveCheck(url);
        if (liveResult && liveResult.findings.some((f) => f.weight > 0)) {
          components.push({ source: 'live_check', score: liveResult.score, weight: 0.9 });
        }
        // If the link lands on a different site, analyse the real destination too.
        if (liveResult.reachable && liveResult.crossDomainRedirect && liveResult.finalUrl) {
          const d = await engineClient.analyzeUrl(liveResult.finalUrl);
          destination = { url: liveResult.finalUrl, riskLevel: d.riskLevel, score: d.score, findings: d.findings, ml: d.ml, anatomy: d.anatomy };
          components.push({ source: 'final_destination', score: Math.max(d.score, d.ml?.available ? d.ml.score : 0), weight: 0.8 });
        }
      } catch (e) {
        console.warn('[scan:url] live check failed:', e.message);
      }
    }

    const combinedFindings = [...ruleResult.findings, ...(liveResult?.findings || [])];
    const mf = mlFinding(ml, 'ml_url_classifier', 'C++ ML URL model (Gradient Boosted Trees + char n-gram Logistic Regression)');
    if (mf) combinedFindings.push(mf);
    if (ml.adjustment) combinedFindings.push({ indicator: 'ml_adjusted_for_official_domain', detail: ml.adjustment, weight: 0 });
    if (destination) {
      for (const f of destination.findings.filter((x) => x.weight > 0).slice(0, 4))
        combinedFindings.push({ ...f, indicator: `destination_${f.indicator}`, detail: `Final destination: ${f.detail}` });
    }

    const fused = await engineClient.fuse(components, combinedFindings);
    let explanation = null;
    if (geminiService.isConfigured()) {
      try {
        explanation = await geminiService.generateExplanation({
          category: 'malicious_url', riskLevel: fused.riskLevel, score: fused.finalScore, findings: combinedFindings,
        });
      } catch (e) {
        console.warn('[scan:url] Gemini explanation failed:', e.message);
      }
    }
    const recommendedActions = explanation?.recommendedActions || recommendFallbackActions('malicious_url', fused.riskLevel);

    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'url',
      inputSummary: url.slice(0, 300),
      engineResult: ruleResult,
      aiResult: liveResult,
      mlResult: ml,
      finalScore: fused.finalScore,
      riskLevel: fused.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });
    const threat = await createThreatIfNeeded({ scan, category: 'malicious_url' });

    res.json(withMitre({
      scanId: scan.id,
      host: ruleResult.host,
      riskLevel: fused.riskLevel,
      score: fused.finalScore,
      findings: combinedFindings,
      anatomy: ruleResult.anatomy,
      trustedBrandDomain: ruleResult.trustedBrandDomain,
      ml,
      liveCheck: liveResult ? {
        reachable: liveResult.reachable, partial: liveResult.partial, error: liveResult.error, finalUrl: liveResult.finalUrl,
        redirectChain: liveResult.redirectChain, crossDomainRedirect: liveResult.crossDomainRedirect, certificate: liveResult.certificate,
        dns: liveResult.dns, domainAge: liveResult.domainAge, loginPage: liveResult.loginPage, page: liveResult.page,
        safeBrowsing: liveResult.safeBrowsing, score: liveResult.score,
      } : null,
      destination,
      scoreComponents: components,
      aiExplanation: explanation?.explanation || null,
      recommendedActions,
      threatCreated: Boolean(threat),
    }, 'malicious_url'));
  } catch (err) {
    res.status(500).json({ error: 'URL scan failed', detail: err.message });
  }
}

// ---------- Deepfake / digital impersonation: image analysis (+ QR-phishing) ----------
async function scanImage(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: 'image file is required (field name "image")' });
    const imageBase64 = req.file.buffer.toString('base64');
    const mimeType = req.file.mimetype;

    // QR-code phishing: decode first; the payload goes through the same URL/text engines.
    const qrPayload = await qrService.decodeQrFromBuffer(req.file.buffer);
    let qrAnalysis = null;
    if (qrPayload) {
      const looksLikeUrl = /^https?:\/\//i.test(qrPayload) || /^www\./i.test(qrPayload);
      qrAnalysis = looksLikeUrl
        ? { type: 'url', payload: qrPayload, result: await engineClient.analyzeUrl(qrPayload) }
        : { type: 'text', payload: qrPayload, result: await engineClient.analyzeText(qrPayload, '') };
    }

    const forensicResult = await engineClient.analyzeImage(imageBase64);
    const ml = forensicResult.ml || { available: false };

    let aiResult = null;
    if (geminiService.isConfigured()) {
      try {
        aiResult = await geminiService.analyzeImageContent(imageBase64, mimeType, forensicResult.findings);
      } catch (e) {
        console.warn('[scan:image] Gemini vision call failed:', e.message);
      }
    }

    const components = [{ source: 'forensic_signals', score: forensicResult.score, weight: 0.5 }];
    // The image ML model is experimental (see model card), so it gets a low weight.
    const mlc = mlComponent(ml, 0.35, 'ml_image_manipulation');
    if (mlc) components.push(mlc);
    if (aiResult && !aiResult.error) {
      const aiRiskScore = 100 - (aiResult.authenticityScore ?? 100);
      components.push({ source: 'gemini_vision', score: aiRiskScore, weight: 1.0 });
    }
    if (qrAnalysis) {
      const qrMl = qrAnalysis.result.ml?.available ? qrAnalysis.result.ml.score : 0;
      components.push({ source: 'qr_payload', score: Math.max(qrAnalysis.result.score, qrMl), weight: 1.0 });
    }

    const combinedFindings = [
      ...forensicResult.findings,
      ...((aiResult?.indicators || []).map((i) => ({ indicator: 'ai_visual_indicator', detail: i, weight: 15 }))),
      ...(qrAnalysis ? [{ indicator: 'qr_code_detected', detail: `Image contains a QR code decoding to: ${qrAnalysis.payload.slice(0, 200)}`, weight: 10 }, ...qrAnalysis.result.findings] : []),
    ];
    if (ml.available && ml.probability >= 0.5) {
      const where = (ml.suspiciousBlocks || []).slice(0, 2).map((b) => `(${b.x},${b.y})`).join(', ');
      combinedFindings.push({ indicator: 'ml_manipulation_model', detail: `Experimental C++ manipulation model rates this ${Math.round(ml.probability * 100)}% likely edited${where ? `; most suspicious 32x32 regions at ${where}` : ''}`, weight: Math.round(ml.score / 6) });
    }
    const fused = await engineClient.fuse(components, combinedFindings);

    const category = qrAnalysis ? 'phishing' : 'deepfake';
    let explanation = null;
    if (geminiService.isConfigured()) {
      try {
        explanation = await geminiService.generateExplanation({ category, riskLevel: fused.riskLevel, score: fused.finalScore, findings: combinedFindings });
      } catch (e) { /* non-fatal */ }
    }
    const recommendedActions = explanation?.recommendedActions || recommendFallbackActions(category, fused.riskLevel);

    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'image',
      inputSummary: qrAnalysis ? `QR code -> ${qrAnalysis.payload.slice(0, 250)}` : req.file.originalname,
      engineResult: forensicResult,
      aiResult: qrAnalysis ? { ...aiResult, qr: qrAnalysis } : aiResult,
      mlResult: ml,
      finalScore: fused.finalScore,
      riskLevel: fused.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });
    const threat = await createThreatIfNeeded({ scan, category });

    res.json(withMitre({
      scanId: scan.id,
      riskLevel: fused.riskLevel,
      score: fused.finalScore,
      authenticityScore: aiResult?.authenticityScore ?? null,
      qrDetected: Boolean(qrAnalysis),
      qrPayload: qrAnalysis?.payload || null,
      findings: combinedFindings,
      ml,
      scoreComponents: components,
      aiExplanation: explanation?.explanation || aiResult?.explanation || null,
      recommendedActions,
      threatCreated: Boolean(threat),
      geminiConfigured: geminiService.isConfigured(),
    }, category));
  } catch (err) {
    res.status(500).json({ error: 'Image scan failed', detail: err.message });
  }
}

// ---------- Voice-clone / audio deepfake ----------
async function scanAudio(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: 'audio file is required (field name "audio")' });
    const mimeType = req.file.mimetype || 'audio/wav';
    const isWav = /wav/i.test(mimeType) || /\.wav$/i.test(req.file.originalname || '');
    // Non-WAV uploads (mp3/m4a/ogg/webm) are converted so the C++ models can run.
    let wavBuffer = isWav ? req.file.buffer : videoService.toWav16k(req.file.buffer, (req.file.originalname || '').split('.').pop());
    const converted = !isWav && Boolean(wavBuffer);
    if (!wavBuffer) wavBuffer = req.file.buffer;
    const audioBase64 = req.file.buffer.toString('base64');

    const forensicResult = await engineClient.analyzeAudio(wavBuffer.toString('base64'));
    const ml = forensicResult.ml || { available: false };

    let aiResult = null;
    if (geminiService.isConfigured()) {
      try {
        aiResult = await geminiService.analyzeAudioContent(audioBase64, mimeType, forensicResult.findings);
      } catch (e) {
        console.warn('[scan:audio] Gemini audio call failed:', e.message);
      }
    }

    const components = [{ source: 'forensic_signals', score: forensicResult.score, weight: 0.5 }];
    const mlc = mlComponent(ml, 0.8, 'ml_voice_model');
    if (mlc) components.push(mlc);
    if (aiResult && !aiResult.error) {
      const aiRiskScore = 100 - (aiResult.authenticityScore ?? 100);
      components.push({ source: 'gemini_audio', score: aiRiskScore, weight: 1.0 });
    }
    const combinedFindings = [
      ...forensicResult.findings,
      ...((aiResult?.indicators || []).map((i) => ({ indicator: 'ai_audio_indicator', detail: i, weight: 15 }))),
    ];
    const mf = mlFinding(ml, 'ml_synthetic_voice', 'C++ voice ML model (Gradient Boosted Trees on MFCC + spectral features)');
    if (mf) combinedFindings.push(mf);
    const fused = await engineClient.fuse(components, combinedFindings);

    let explanation = null;
    if (geminiService.isConfigured()) {
      try {
        explanation = await geminiService.generateExplanation({ category: 'deepfake', riskLevel: fused.riskLevel, score: fused.finalScore, findings: combinedFindings });
      } catch (e) { /* non-fatal */ }
    }
    const recommendedActions = explanation?.recommendedActions || recommendFallbackActions('deepfake', fused.riskLevel);

    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'audio',
      inputSummary: req.file.originalname,
      engineResult: forensicResult,
      aiResult,
      mlResult: ml,
      finalScore: fused.finalScore,
      riskLevel: fused.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });
    const threat = await createThreatIfNeeded({ scan, category: 'deepfake' });

    res.json(withMitre({
      scanId: scan.id,
      riskLevel: fused.riskLevel,
      score: fused.finalScore,
      authenticityScore: aiResult?.authenticityScore ?? null,
      findings: combinedFindings,
      ml,
      convertedToWav: converted,
      scoreComponents: components,
      aiExplanation: explanation?.explanation || aiResult?.explanation || null,
      recommendedActions,
      threatCreated: Boolean(threat),
      geminiConfigured: geminiService.isConfigured(),
    }, 'deepfake'));
  } catch (err) {
    res.status(500).json({ error: 'Audio scan failed', detail: err.message });
  }
}

// ---------- Deepfake video (frames + voice track) ----------
async function scanVideo(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: 'video file is required (field name "video")' });

    const { frames, ffmpegAvailable, durationSeconds } = videoService.extractFrames(req.file.buffer, 6);
    if (!ffmpegAvailable) {
      return res.status(503).json({ error: 'ffmpeg is not installed on the backend host; video analysis requires ffmpeg to extract frames. See README for installation.' });
    }
    if (frames.length === 0) {
      return res.status(400).json({ error: 'Could not extract any frames from the uploaded video. Is it a valid video file?' });
    }

    // C++ forensic layer + image ML on every extracted frame.
    const perFrameResults = [];
    for (const frame of frames) perFrameResults.push(await engineClient.analyzeImage(frame.base64));
    const maxForensicScore = Math.max(...perFrameResults.map((r) => r.score));
    const forensicFindings = perFrameResults.flatMap((r, i) => r.findings.map((f) => ({ ...f, detail: `[frame ${i + 1}] ${f.detail}` })));
    const frameMl = perFrameResults.map((r) => r.ml).filter((m) => m && m.available);
    const frameMlProbs = frameMl.map((m) => m.probability);
    // Temporal inconsistency: large frame-to-frame swings in manipulation probability.
    const swing = frameMlProbs.length > 1 ? Math.max(...frameMlProbs) - Math.min(...frameMlProbs) : 0;
    const meanFrameMl = frameMlProbs.length ? frameMlProbs.reduce((a, b) => a + b, 0) / frameMlProbs.length : null;

    // Voice track -> synthetic-voice model (video calls / talking-head deepfakes).
    let voice = null;
    const wav = videoService.extractAudioWav(req.file.buffer);
    if (wav && wav.length > 44 + 16000) {
      try {
        const a = await engineClient.analyzeAudio(wav.toString('base64'));
        voice = { forensic: { score: a.score, riskLevel: a.riskLevel, findings: a.findings }, ml: a.ml };
      } catch (e) { /* no usable audio track */ }
    }

    let aiResult = null;
    if (geminiService.isConfigured()) {
      try {
        aiResult = await geminiService.analyzeVideoFrames(frames.map((f) => f.base64), forensicFindings);
      } catch (e) {
        console.warn('[scan:video] Gemini video call failed:', e.message);
      }
    }

    const components = [{ source: 'forensic_signals', score: maxForensicScore, weight: 0.5 }];
    if (meanFrameMl !== null) components.push({ source: 'ml_frame_manipulation', score: Math.round(meanFrameMl * 100), weight: 0.3 });
    if (voice?.ml?.available) components.push({ source: 'ml_voice_model', score: voice.ml.score, weight: 0.8 });
    if (aiResult && !aiResult.error) {
      const aiRiskScore = 100 - (aiResult.authenticityScore ?? 100);
      components.push({ source: 'gemini_video', score: aiRiskScore, weight: 1.0 });
    }
    const combinedFindings = [
      ...forensicFindings,
      ...((aiResult?.indicators || []).map((i) => ({ indicator: 'ai_video_indicator', detail: i, weight: 15 }))),
    ];
    if (meanFrameMl !== null && meanFrameMl >= 0.5)
      combinedFindings.push({ indicator: 'ml_frame_manipulation', detail: `Experimental manipulation model: average ${Math.round(meanFrameMl * 100)}% across ${frameMl.length} frames`, weight: 8 });
    if (swing >= 0.5)
      combinedFindings.push({ indicator: 'temporal_inconsistency', detail: `Manipulation likelihood swings by ${Math.round(swing * 100)} points between frames (inconsistent editing over time)`, weight: 10 });
    if (voice?.ml?.available && voice.ml.probability >= 0.5)
      combinedFindings.push({ indicator: 'ml_synthetic_voice_in_video', detail: `Voice track rated ${Math.round(voice.ml.probability * 100)}% likely synthetic by the C++ voice model`, weight: Math.round(voice.ml.score / 4) });
    const fused = await engineClient.fuse(components, combinedFindings);

    let explanation = null;
    if (geminiService.isConfigured()) {
      try {
        explanation = await geminiService.generateExplanation({ category: 'deepfake', riskLevel: fused.riskLevel, score: fused.finalScore, findings: combinedFindings });
      } catch (e) { /* non-fatal */ }
    }
    const recommendedActions = explanation?.recommendedActions || recommendFallbackActions('deepfake', fused.riskLevel);
    const ml = { available: frameMl.length > 0 || Boolean(voice?.ml?.available), frames: frameMlProbs, meanFrameProbability: meanFrameMl, temporalSwing: swing, voice: voice?.ml || null };

    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'video',
      inputSummary: `${req.file.originalname} (${durationSeconds?.toFixed(1)}s, ${frames.length} frames sampled)`,
      engineResult: { perFrameResults: perFrameResults.map((r) => ({ score: r.score, findings: r.findings })), maxForensicScore, voice },
      aiResult,
      mlResult: ml,
      finalScore: fused.finalScore,
      riskLevel: fused.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });
    const threat = await createThreatIfNeeded({ scan, category: 'deepfake' });

    res.json(withMitre({
      scanId: scan.id,
      riskLevel: fused.riskLevel,
      score: fused.finalScore,
      authenticityScore: aiResult?.authenticityScore ?? null,
      framesAnalyzed: frames.length,
      findings: combinedFindings,
      ml,
      scoreComponents: components,
      aiExplanation: explanation?.explanation || aiResult?.explanation || null,
      recommendedActions,
      threatCreated: Boolean(threat),
      geminiConfigured: geminiService.isConfigured(),
    }, 'deepfake'));
  } catch (err) {
    res.status(500).json({ error: 'Video scan failed', detail: err.message });
  }
}

// ---------- Technical threat detection: system/network/API/auth logs ----------
async function scanLogs(req, res) {
  try {
    const { entries } = req.body;
    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'entries (a non-empty array of log objects) is required' });
    }

    const result = await engineClient.analyzeLogs(entries);
    const ml = result.ml || { available: false };
    const anomalous = (ml.entities || []).filter((e) => e.isAnomaly);

    let explanation = null;
    if (geminiService.isConfigured()) {
      try {
        explanation = await geminiService.summariseLogFindings(result);
      } catch (e) {
        console.warn('[scan:logs] Gemini summarisation failed:', e.message);
      }
    }
    const recommendedActions = explanation?.recommendedActions || recommendFallbackActions('technical_threat', result.riskLevel);

    // Fuse rule score with the Isolation Forest behaviour model.
    const components = [{ source: 'rule_engine', score: result.score, weight: 1.0 }];
    const mlc = mlComponent(ml, 0.7, 'ml_behaviour_model');
    if (mlc) components.push(mlc);
    const mlFindings = anomalous.map((e) => ({
      indicator: 'ml_behaviour_anomaly',
      category: 'anomalous_behaviour',
      detail: `Isolation Forest flags ${e.entity} as behaving unlike normal users/clients (anomaly score ${e.anomalyScore.toFixed(2)}; most unusual: ${[e.outOfRangeFeature, ...(e.topFeatures || []).map((t) => t.feature)].filter(Boolean).slice(0, 3).join(', ')})`,
      weight: 15,
    }));
    const fused = await engineClient.fuse(components, [...result.findings, ...mlFindings]);

    // A log batch can surface several threat categories at once, so create
    // one threat per non-empty category rather than one per scan.
    const scan = await Scan.create({
      userId: req.user?.id || null,
      scanType: 'log_upload',
      inputSummary: `${entries.length} log entries analysed`,
      engineResult: result,
      mlResult: ml,
      finalScore: fused.finalScore,
      riskLevel: fused.riskLevel,
      recommendedAction: recommendedActions.join('; '),
    });

    const createdThreats = [];
    for (const [category, findings] of Object.entries(result.categoryBreakdown)) {
      if (findings.length === 0) continue;
      const categoryMaxWeight = Math.max(...findings.map((f) => f.weight));
      const categoryRisk = categoryMaxWeight >= 35 ? 'High' : categoryMaxWeight >= 18 ? 'Medium' : 'Low';
      if (categoryRisk === 'Low') continue;
      const threat = await Threat.create({
        scanId: scan.id, category, riskLevel: categoryRisk, targetUserId: req.user?.id || null,
        recommendedAction: recommendedActions.join('; '), status: 'open',
      });
      createdThreats.push({ category, riskLevel: categoryRisk, threatId: threat.id });
    }
    if (anomalous.length && !createdThreats.length) {
      const threat = await Threat.create({
        scanId: scan.id, category: 'technical_threat', riskLevel: 'Medium', targetUserId: req.user?.id || null,
        recommendedAction: recommendedActions.join('; '), status: 'open',
      });
      createdThreats.push({ category: 'technical_threat', riskLevel: 'Medium', threatId: threat.id, source: 'ml' });
    }

    res.json({
      scanId: scan.id,
      riskLevel: fused.riskLevel,
      score: fused.finalScore,
      ruleScore: result.score,
      entriesAnalyzed: result.entriesAnalyzed,
      categoryBreakdown: result.categoryBreakdown,
      findings: [...result.findings, ...mlFindings],
      ml,
      scoreComponents: components,
      aiExplanation: explanation?.explanation || null,
      recommendedActions,
      threatsCreated: createdThreats,
      mitreAttack: createdThreats.map((t) => ({ category: t.category, techniques: mitreMapping.techniquesForCategory(t.category) })),
    });
  } catch (err) {
    res.status(500).json({ error: 'Log scan failed', detail: err.message });
  }
}

async function history(req, res) {
  const where = req.user.role === 'admin' ? {} : { userId: req.user.id };
  const scans = await Scan.findAll({ where, order: [['createdAt', 'DESC']], limit: 100 });
  res.json({ scans });
}

async function getOne(req, res) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.id || '')) return res.status(404).json({ error: 'Scan not found' });
  const scan = await Scan.findByPk(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  if (req.user.role !== 'admin' && scan.userId !== req.user.id) {
    return res.status(403).json({ error: 'Not authorized to view this scan' });
  }
  res.json({ scan });
}

// ---------- Scan history: delete (with undo), restore, clear all ----------
// Deletion is a soft delete: rows get deleted_at and disappear from history,
// the dashboard and every other view immediately. They can be restored during
// the undo window; purgeDeleted() (run by server.js) removes them for good.
const UNDO_WINDOW_SECONDS = 60;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function canModify(req, scan) {
  return req.user.role === 'admin' || (scan.userId && scan.userId === req.user.id);
}

async function removeScan(req, res) {
  if (!UUID_RE.test(req.params.id || '')) return res.status(404).json({ error: 'Scan not found' });
  try {
    const scan = await Scan.findByPk(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canModify(req, scan)) return res.status(403).json({ error: 'Not authorized to delete this scan' });
    await sequelize.transaction(async (transaction) => {
      await Threat.destroy({ where: { scanId: scan.id }, transaction });
      await scan.destroy({ transaction });
    });
    res.json({ deleted: [scan.id], undoWindowSeconds: UNDO_WINDOW_SECONDS });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete the scan', detail: err.message });
  }
}

async function clearHistory(req, res) {
  try {
    const scans = await Scan.findAll({ where: { userId: req.user.id }, attributes: ['id'] });
    const ids = scans.map((s) => s.id);
    if (ids.length) {
      await sequelize.transaction(async (transaction) => {
        await Threat.destroy({ where: { scanId: { [Op.in]: ids } }, transaction });
        await Scan.destroy({ where: { id: { [Op.in]: ids } }, transaction });
      });
    }
    res.json({ deleted: ids, undoWindowSeconds: UNDO_WINDOW_SECONDS });
  } catch (err) {
    res.status(500).json({ error: 'Could not clear the scan history', detail: err.message });
  }
}

async function restoreScans(req, res) {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((x) => typeof x === 'string' && UUID_RE.test(x)).slice(0, 5000) : [];
    if (!ids.length) return res.status(400).json({ error: 'ids is required' });
    const scans = await Scan.findAll({ where: { id: { [Op.in]: ids } }, paranoid: false });
    const allowed = scans.filter((s) => s.deletedAt && canModify(req, s)).map((s) => s.id);
    if (!allowed.length) return res.status(410).json({ error: 'Nothing to restore: the undo window has passed' });
    await sequelize.transaction(async (transaction) => {
      await Scan.restore({ where: { id: { [Op.in]: allowed } }, transaction });
      await Threat.restore({ where: { scanId: { [Op.in]: allowed } }, transaction });
    });
    res.json({ restored: allowed });
  } catch (err) {
    res.status(500).json({ error: 'Could not restore', detail: err.message });
  }
}

// Permanently removes scans deleted longer than the undo window ago
// (their threats go with them through ON DELETE CASCADE).
async function purgeDeleted() {
  const cutoff = new Date(Date.now() - UNDO_WINDOW_SECONDS * 1000);
  return Scan.destroy({ where: { deletedAt: { [Op.lt]: cutoff } }, force: true, paranoid: false });
}

module.exports = { scanText, scanUrl, scanImage, scanAudio, scanVideo, scanLogs, history, getOne, removeScan, clearHistory, restoreScans, purgeDeleted, recommendFallbackActions, createThreatIfNeeded };
