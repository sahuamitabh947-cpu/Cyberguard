// Accuracy/performance evaluation harness for CyberGuard's C++ rule engines.
// Runs every labeled sample in dataset.json through the live detection
// engine (must be running -- see README) and reports precision, recall,
// F1, and accuracy, satisfying the PRD's "accuracy/performance evaluation"
// deliverable. This evaluates the deterministic rule engines only (not the
// optional Gemini AI layer), so results are 100% reproducible offline with
// no API key required.
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const ENGINE_URL = process.env.ENGINE_URL || 'http://127.0.0.1:5050';
const RISK_ORDER = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
const THRESHOLD_INDEX = RISK_ORDER.indexOf('Medium'); // Medium+ => predicted "malicious/phishing"

function predictedPositive(riskLevel) {
  return RISK_ORDER.indexOf(riskLevel) >= THRESHOLD_INDEX;
}

function computeMetrics(rows) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of rows) {
    const actualPositive = r.label === 'phishing';
    const predPositive = predictedPositive(r.riskLevel);
    if (actualPositive && predPositive) tp++;
    else if (!actualPositive && predPositive) fp++;
    else if (!actualPositive && !predPositive) tn++;
    else fn++;
  }
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = rows.length > 0 ? (tp + tn) / rows.length : 0;
  return { tp, fp, tn, fn, precision, recall, f1, accuracy, n: rows.length };
}

function pct(x) { return (x * 100).toFixed(1) + '%'; }

async function main() {
  const dataset = JSON.parse(fs.readFileSync(path.join(__dirname, 'dataset.json'), 'utf8'));
  const client = axios.create({ baseURL: ENGINE_URL, timeout: 5000 });

  try {
    await client.get('/health');
  } catch (e) {
    console.error(`Could not reach the detection engine at ${ENGINE_URL}.`);
    console.error('Start it first: cd detection-engine-cpp && ./build/cyberguard_engine (or docker compose up engine)');
    process.exit(1);
  }

  console.log(`Evaluating against engine at ${ENGINE_URL}\n`);

  const textRows = [];
  for (const sample of dataset.textSamples) {
    const { data } = await client.post('/analyze/text', { text: sample.text, claimedSender: sample.claimedSender });
    textRows.push({ id: sample.id, label: sample.label, riskLevel: data.riskLevel, score: data.score });
    console.log(`[text] ${sample.id.padEnd(5)} label=${sample.label.padEnd(11)} predicted=${data.riskLevel.padEnd(9)} score=${data.score}`);
  }

  console.log('');
  const urlRows = [];
  for (const sample of dataset.urlSamples) {
    const { data } = await client.post('/analyze/url', { url: sample.url });
    urlRows.push({ id: sample.id, label: sample.label, riskLevel: data.riskLevel, score: data.score });
    console.log(`[url]  ${sample.id.padEnd(5)} label=${sample.label.padEnd(11)} predicted=${data.riskLevel.padEnd(9)} score=${data.score}`);
  }

  const textMetrics = computeMetrics(textRows);
  const urlMetrics = computeMetrics(urlRows);
  const overallMetrics = computeMetrics([...textRows, ...urlRows]);

  const report = {
    generatedAt: new Date().toISOString(),
    threshold: `riskLevel >= ${RISK_ORDER[THRESHOLD_INDEX]} counted as predicted phishing/malicious`,
    text: textMetrics,
    url: urlMetrics,
    overall: overallMetrics,
    rows: { text: textRows, url: urlRows },
  };

  fs.writeFileSync(path.join(__dirname, 'report.json'), JSON.stringify(report, null, 2));

  const md = `# CyberGuard Rule-Engine Evaluation Report

Generated: ${report.generatedAt}
Threshold: ${report.threshold}

## Text / Message Engine (phishing & social-engineering)
| Metric | Value |
|---|---|
| Samples | ${textMetrics.n} |
| Accuracy | ${pct(textMetrics.accuracy)} |
| Precision | ${pct(textMetrics.precision)} |
| Recall | ${pct(textMetrics.recall)} |
| F1 | ${pct(textMetrics.f1)} |
| TP / FP / TN / FN | ${textMetrics.tp} / ${textMetrics.fp} / ${textMetrics.tn} / ${textMetrics.fn} |

## URL Engine (malicious URL / website detection)
| Metric | Value |
|---|---|
| Samples | ${urlMetrics.n} |
| Accuracy | ${pct(urlMetrics.accuracy)} |
| Precision | ${pct(urlMetrics.precision)} |
| Recall | ${pct(urlMetrics.recall)} |
| F1 | ${pct(urlMetrics.f1)} |
| TP / FP / TN / FN | ${urlMetrics.tp} / ${urlMetrics.fp} / ${urlMetrics.tn} / ${urlMetrics.fn} |

## Overall
| Metric | Value |
|---|---|
| Samples | ${overallMetrics.n} |
| Accuracy | ${pct(overallMetrics.accuracy)} |
| Precision | ${pct(overallMetrics.precision)} |
| Recall | ${pct(overallMetrics.recall)} |
| F1 | ${pct(overallMetrics.f1)} |

*Note: this evaluates the deterministic C++ rule engines only. Enabling the Gemini AI layer typically shifts recall and precision further (it catches indicators the rule engine misses, at the cost of external API latency/cost) -- rerun with GEMINI_API_KEY configured against the full \`/api/scan/*\` backend endpoints for an end-to-end (rule+AI) evaluation.*
`;
  fs.writeFileSync(path.join(__dirname, 'report.md'), md);

  console.log('\n=== Overall ===');
  console.log(`Accuracy:  ${pct(overallMetrics.accuracy)}`);
  console.log(`Precision: ${pct(overallMetrics.precision)}`);
  console.log(`Recall:    ${pct(overallMetrics.recall)}`);
  console.log(`F1:        ${pct(overallMetrics.f1)}`);
  console.log('\nWritten: evaluation/report.json, evaluation/report.md');
}

main().catch((err) => {
  console.error('Evaluation failed:', err.message);
  process.exit(1);
});
