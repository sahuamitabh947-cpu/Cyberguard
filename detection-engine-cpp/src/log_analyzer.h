#pragma once
#include <string>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Analyses a batch of structured log entries (authentication, system, network,
// or API logs) for technical cyber-threat indicators that are NOT covered by
// the phishing/URL/image/login-anomaly engines: malware-like process/file
// behaviour, network scanning patterns, API abuse (rate/volume spikes),
// data-exfiltration signatures, and insider-threat access patterns.
//
// Input is a JSON array of log entries. Each entry may contain any subset of:
//   timestamp (ISO8601 or unix seconds), sourceIp, userId, eventType,
//   destinationPort, destinationHost, bytesTransferred, processName,
//   filePath, httpStatus, apiEndpoint
// Missing fields are simply not used by the rules that need them.
class LogAnalyzer {
public:
    json analyze(const json& logEntries) const;

private:
    json detectPortScan(const json& entries) const;
    json detectApiAbuse(const json& entries) const;
    json detectDataExfiltration(const json& entries) const;
    json detectInsiderThreat(const json& entries) const;
    json detectMalwareIndicators(const json& entries) const;
};

} // namespace cyberguard
