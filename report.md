# CyberGuard Rule-Engine Evaluation Report

Generated: 2026-09-05T20:50:45.977Z
Threshold: riskLevel >= Medium counted as predicted phishing/malicious

## Text / Message Engine (phishing & social-engineering)
| Metric | Value |
|---|---|
| Samples | 30 |
| Accuracy | 96.7% |
| Precision | 100.0% |
| Recall | 93.3% |
| F1 | 96.6% |
| TP / FP / TN / FN | 14 / 0 / 15 / 1 |

## URL Engine (malicious URL / website detection)
| Metric | Value |
|---|---|
| Samples | 30 |
| Accuracy | 86.7% |
| Precision | 100.0% |
| Recall | 73.3% |
| F1 | 84.6% |
| TP / FP / TN / FN | 11 / 0 / 15 / 4 |

## Overall
| Metric | Value |
|---|---|
| Samples | 60 |
| Accuracy | 91.7% |
| Precision | 100.0% |
| Recall | 83.3% |
| F1 | 90.9% |

*Note: this evaluates the deterministic C++ rule engines only. Enabling the Gemini AI layer typically shifts recall and precision further (it catches indicators the rule engine misses, at the cost of external API latency/cost) -- rerun with GEMINI_API_KEY configured against the full `/api/scan/*` backend endpoints for an end-to-end (rule+AI) evaluation.*
