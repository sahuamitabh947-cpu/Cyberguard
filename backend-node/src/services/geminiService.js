const axios = require('axios');
const systemMode = require('./systemMode');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
// Model name is env-configurable because Google updates/retires Gemini model
// names periodically -- check https://ai.google.dev/gemini-api/docs/models
// if this default ever 404s for you.
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const BASE_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// Gemini is used only when a key is configured AND the system is online.
function isConfigured() {
  return Boolean(GEMINI_API_KEY) && systemMode.isOnline();
}

async function callGemini(parts, { jsonMode = true } = {}) {
  if (!isConfigured()) {
    throw new Error('GEMINI_API_KEY is not set. Add it to backend-node/.env to enable AI analysis.');
  }
  const body = {
    contents: [{ role: 'user', parts }],
    generationConfig: {
      temperature: 0.2,
      ...(jsonMode ? { responseMimeType: 'application/json' } : {}),
    },
  };
  const { data } = await axios.post(`${BASE_URL}?key=${GEMINI_API_KEY}`, body, { timeout: 20000 });
  const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text).join('') || '';
  return text;
}

// Classifies raw email/SMS/message text for phishing & social-engineering
// indicators, and returns a structured verdict. The C++ rule-engine's
// findings are passed in as context so Gemini can reason on top of them
// rather than duplicate that work (Hybrid Rule + AI model, per PRD).
async function classifyPhishingText(text, claimedSender, ruleFindings) {
  const prompt = `You are a cybersecurity SOC analyst assistant. Analyse the following message for phishing, social-engineering, or scam indicators.
Claimed sender: ${claimedSender || 'unknown'}
A local rule engine already found these indicators: ${JSON.stringify(ruleFindings)}

Message:
"""
${text}
"""

Respond ONLY with JSON of this exact shape:
{
  "isSuspicious": boolean,
  "confidenceScore": number (0-100),
  "category": "phishing" | "social_engineering" | "spam" | "legitimate",
  "explanation": "one or two sentence explanation in the style of a SOC analyst, naming the specific evidence",
  "additionalIndicators": ["short indicator phrase", ...]
}`;
  const raw = await callGemini([{ text: prompt }]);
  return safeParseJson(raw);
}

// Multimodal image analysis for the deepfake / digital-impersonation module.
// mimeType e.g. "image/jpeg". imageBase64 must NOT include the data: prefix.
async function analyzeImageContent(imageBase64, mimeType, forensicFindings) {
  const prompt = `You are a digital-forensics assistant helping assess whether an image may be AI-generated, manipulated, or used for impersonation/deepfake purposes.
A local forensic signal extractor already found: ${JSON.stringify(forensicFindings)}

Look at the image itself for: unnatural skin/texture blending, inconsistent lighting or shadows, warped background elements, asymmetric or malformed facial features, unnatural eyes/teeth, text or logo artifacts consistent with impersonation of a brand or official document, or other signs of synthetic generation or editing.

Respond ONLY with JSON of this exact shape:
{
  "authenticityScore": number (0-100, 100 = fully authentic/unmanipulated),
  "likelyManipulated": boolean,
  "explanation": "one or two sentence explanation naming the specific visual evidence you observed",
  "indicators": ["short indicator phrase", ...]
}`;
  const raw = await callGemini([
    { text: prompt },
    { inline_data: { mime_type: mimeType, data: imageBase64 } },
  ]);
  return safeParseJson(raw);
}

// Generates the human-readable "Explainable AI" narrative the PRD asks for,
// e.g. "High Risk: The sender domain closely resembles ... " — fuses all
// upstream findings (rule engines + AI) into one paragraph plus a
// recommended response action list.
async function generateExplanation({ category, riskLevel, score, findings }) {
  const prompt = `You are writing the human-readable summary shown to a SOC analyst on a security dashboard.
Category: ${category}
Risk level: ${riskLevel}
Score: ${score}/100
Findings: ${JSON.stringify(findings)}

Write ONLY a JSON object of this exact shape:
{
  "explanation": "a single dense paragraph, 2-3 sentences, in the exact style of: 'High Risk: The sender domain closely resembles an authorised organisation, the message requests urgent credential verification, and the embedded URL redirects to an unrelated domain.' Be specific to the findings given, do not invent facts not present in the findings.",
  "recommendedActions": ["action from this set only: Block suspicious URL, Quarantine email, Warn the user, Require additional authentication, Revoke active session, Block suspicious IP/device, Flag multimedia for manual verification, Report impersonation, Notify administrator/SOC, Escalate the incident for investigation"]
}`;
  const raw = await callGemini([{ text: prompt }]);
  return safeParseJson(raw);
}

// Audio deepfake / voice-clone analysis. audioBase64 must NOT include the
// data: prefix. mimeType e.g. "audio/wav".
async function analyzeAudioContent(audioBase64, mimeType, forensicFindings) {
  const prompt = `You are a digital-forensics assistant assessing whether an audio clip may be an AI-generated or cloned voice (voice-clone/deepfake audio), used for impersonation or fraud.
A local signal-processing layer already found: ${JSON.stringify(forensicFindings)}

Listen to the audio for: unnatural prosody or rhythm, robotic or metallic timbre, inconsistent breathing/mouth sounds, abrupt splices, background-noise inconsistency, or a voice that claims an identity (e.g. a named official, executive, or relative) inconsistent with how that person would plausibly sound or speak.

Respond ONLY with JSON of this exact shape:
{
  "authenticityScore": number (0-100, 100 = fully authentic human speech),
  "likelyVoiceClone": boolean,
  "explanation": "one or two sentence explanation naming the specific audio evidence you heard",
  "indicators": ["short indicator phrase", ...]
}`;
  const raw = await callGemini([
    { text: prompt },
    { inline_data: { mime_type: mimeType, data: audioBase64 } },
  ]);
  return safeParseJson(raw);
}

// Deepfake video analysis over a small set of representative extracted
// frames (base64 JPEGs) rather than the raw video container, since inline
// multi-frame submission works across Gemini API tiers without requiring
// the separate Files API upload flow.
async function analyzeVideoFrames(frameBase64List, forensicFindings) {
  const prompt = `You are a digital-forensics assistant assessing whether a video may be a deepfake or manipulated, based on ${frameBase64List.length} representative frames sampled evenly across its duration.
A local per-frame forensic signal layer already found: ${JSON.stringify(forensicFindings)}

Look across the frames for: inconsistent facial features or lighting between frames, unnatural blending at face/hair boundaries, temporal flicker or warping, mismatched lip movement, or artefacts typical of face-swap/generative video manipulation.

Respond ONLY with JSON of this exact shape:
{
  "authenticityScore": number (0-100, 100 = fully authentic/unmanipulated),
  "likelyManipulated": boolean,
  "explanation": "one or two sentence explanation naming the specific visual evidence across the sampled frames",
  "indicators": ["short indicator phrase", ...]
}`;
  const parts = [{ text: prompt }];
  for (const frame of frameBase64List) {
    parts.push({ inline_data: { mime_type: 'image/jpeg', data: frame } });
  }
  const raw = await callGemini(parts);
  return safeParseJson(raw);
}

// Summarises a batch of technical log-analysis findings (malware/network/
// API-abuse/insider-threat/exfiltration) into the same analyst-narrative
// style used elsewhere, since these findings span several sub-categories
// at once rather than a single scan type.
async function summariseLogFindings({ riskLevel, score, categoryBreakdown }) {
  const prompt = `You are writing the human-readable summary shown to a SOC analyst after a batch log analysis.
Overall risk level: ${riskLevel}
Overall score: ${score}/100
Findings by category: ${JSON.stringify(categoryBreakdown)}

Write ONLY a JSON object of this exact shape:
{
  "explanation": "a single dense paragraph, 2-4 sentences, summarising which categories of technical threat were found and why they matter, referencing only the findings given",
  "recommendedActions": ["action from this set only: Block suspicious IP/device, Require additional authentication, Revoke active session, Notify administrator/SOC, Escalate the incident for investigation"]
}`;
  const raw = await callGemini([{ text: prompt }]);
  return safeParseJson(raw);
}

function safeParseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch (e) {
    // Gemini occasionally wraps JSON in markdown fences despite instructions; strip and retry.
    const cleaned = raw.replace(/```json|```/g, '').trim();
    try {
      return JSON.parse(cleaned);
    } catch (e2) {
      return { error: 'Failed to parse Gemini response', raw };
    }
  }
}

module.exports = { isConfigured, classifyPhishingText, analyzeImageContent, analyzeAudioContent, analyzeVideoFrames, summariseLogFindings, generateExplanation };
