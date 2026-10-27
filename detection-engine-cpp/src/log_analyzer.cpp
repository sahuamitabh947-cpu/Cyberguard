#include "log_analyzer.h"
#include <map>
#include <set>
#include <algorithm>
#include <cmath>

namespace cyberguard {

struct Finding { std::string indicator; std::string detail; int weight; std::string category; };

static json toFindingsJson(const std::vector<Finding>& fs) {
    json arr = json::array();
    for (const auto& f : fs) {
        arr.push_back({ {"indicator", f.indicator}, {"detail", f.detail}, {"weight", f.weight}, {"category", f.category} });
    }
    return arr;
}

static std::string getStr(const json& e, const std::string& key) {
    return e.contains(key) && !e[key].is_null() ? e[key].get<std::string>() : std::string();
}
static double getNum(const json& e, const std::string& key, double def = 0.0) {
    return e.contains(key) && e[key].is_number() ? e[key].get<double>() : def;
}

// ---- 1. Network scanning: many distinct destination ports from one source ----
json LogAnalyzer::detectPortScan(const json& entries) const {
    std::map<std::string, std::set<int>> portsBySource;
    for (const auto& e : entries) {
        std::string src = getStr(e, "sourceIp");
        if (src.empty() || !e.contains("destinationPort")) continue;
        portsBySource[src].insert((int)getNum(e, "destinationPort"));
    }
    std::vector<Finding> findings;
    for (const auto& [src, ports] : portsBySource) {
        if (ports.size() >= 15) {
            findings.push_back({ "port_scan_pattern",
                src + " probed " + std::to_string(ports.size()) + " distinct destination ports, consistent with network/port scanning",
                40, "network_threat" });
        } else if (ports.size() >= 8) {
            findings.push_back({ "elevated_port_diversity",
                src + " contacted " + std::to_string(ports.size()) + " distinct ports, more than typical single-service traffic",
                18, "network_threat" });
        }
    }
    return toFindingsJson(findings);
}

// ---- 2. API abuse: excessive request volume or error-rate spikes per source/endpoint ----
json LogAnalyzer::detectApiAbuse(const json& entries) const {
    std::map<std::string, int> requestsByKey;
    std::map<std::string, int> errorsByKey;
    for (const auto& e : entries) {
        std::string endpoint = getStr(e, "apiEndpoint");
        if (endpoint.empty()) continue;
        std::string src = getStr(e, "sourceIp");
        std::string key = src + "|" + endpoint;
        requestsByKey[key]++;
        int status = (int)getNum(e, "httpStatus", 200);
        if (status >= 400) errorsByKey[key]++;
    }
    std::vector<Finding> findings;
    for (const auto& [key, count] : requestsByKey) {
        std::string src = key.substr(0, key.find('|'));
        std::string endpoint = key.substr(key.find('|') + 1);
        if (count >= 100) {
            findings.push_back({ "api_rate_abuse",
                src + " issued " + std::to_string(count) + " requests to " + endpoint + " within the log window, indicating automated/abusive access rather than normal usage",
                35, "api_abuse" });
        } else if (count >= 40) {
            findings.push_back({ "elevated_api_volume",
                src + " issued " + std::to_string(count) + " requests to " + endpoint,
                15, "api_abuse" });
        }
        auto errIt = errorsByKey.find(key);
        if (errIt != errorsByKey.end() && count > 0) {
            double errorRatio = (double)errIt->second / count;
            if (errorRatio > 0.5 && count >= 10) {
                findings.push_back({ "high_error_ratio",
                    src + " received errors on " + std::to_string((int)(errorRatio * 100)) + "% of requests to " + endpoint + ", consistent with credential stuffing, fuzzing, or endpoint enumeration",
                    25, "api_abuse" });
            }
        }
    }
    return toFindingsJson(findings);
}

// ---- 3. Data exfiltration: abnormally large outbound transfer volumes ----
json LogAnalyzer::detectDataExfiltration(const json& entries) const {
    std::map<std::string, double> bytesByUser;
    std::map<std::string, int> offHoursLargeTransfers;
    for (const auto& e : entries) {
        std::string user = getStr(e, "userId");
        if (user.empty()) user = getStr(e, "sourceIp");
        if (user.empty()) continue;
        double bytes = getNum(e, "bytesTransferred", 0);
        bytesByUser[user] += bytes;
        int hour = (int)getNum(e, "hourOfDay", 12);
        if (bytes > 100.0 * 1024 * 1024 && (hour < 6 || hour > 22)) {
            offHoursLargeTransfers[user]++;
        }
    }
    std::vector<Finding> findings;
    const double GB = 1024.0 * 1024.0 * 1024.0;
    for (const auto& [user, bytes] : bytesByUser) {
        if (bytes > 2 * GB) {
            findings.push_back({ "large_data_transfer",
                user + " transferred " + std::to_string((long)(bytes / GB * 100) / 100.0) + " GB in the log window, well above typical single-user activity",
                40, "data_exfiltration" });
        } else if (bytes > 500.0 * 1024 * 1024) {
            findings.push_back({ "elevated_data_transfer",
                user + " transferred " + std::to_string((long)(bytes / (1024*1024))) + " MB in the log window",
                18, "data_exfiltration" });
        }
    }
    for (const auto& [user, count] : offHoursLargeTransfers) {
        if (count > 0) {
            findings.push_back({ "off_hours_bulk_transfer",
                user + " performed " + std::to_string(count) + " large data transfer(s) outside normal business hours",
                20, "data_exfiltration" });
        }
    }
    return toFindingsJson(findings);
}

// ---- 4. Insider threat: privileged/sensitive event sequences by one user ----
json LogAnalyzer::detectInsiderThreat(const json& entries) const {
    static const std::set<std::string> sensitiveEvents = {
        "permission_change", "role_escalation", "mass_download", "file_delete_bulk",
        "admin_access", "export_data", "disable_logging", "access_after_termination"
    };
    std::map<std::string, int> sensitiveEventCountByUser;
    std::map<std::string, std::set<std::string>> distinctFilesByUser;
    for (const auto& e : entries) {
        std::string user = getStr(e, "userId");
        if (user.empty()) continue;
        std::string eventType = getStr(e, "eventType");
        if (sensitiveEvents.count(eventType)) sensitiveEventCountByUser[user]++;
        std::string filePath = getStr(e, "filePath");
        if (!filePath.empty()) distinctFilesByUser[user].insert(filePath);
    }
    std::vector<Finding> findings;
    for (const auto& [user, count] : sensitiveEventCountByUser) {
        if (count >= 3) {
            findings.push_back({ "privileged_action_cluster",
                user + " performed " + std::to_string(count) + " sensitive/privileged actions (role changes, bulk export/delete, admin access) within the log window",
                35, "insider_threat" });
        } else if (count >= 1) {
            findings.push_back({ "privileged_action",
                user + " performed a sensitive/privileged action in the log window",
                12, "insider_threat" });
        }
    }
    for (const auto& [user, files] : distinctFilesByUser) {
        if (files.size() >= 50) {
            findings.push_back({ "mass_file_access",
                user + " accessed " + std::to_string(files.size()) + " distinct files/paths, consistent with bulk data staging ahead of exfiltration",
                30, "insider_threat" });
        }
    }
    return toFindingsJson(findings);
}

// ---- 5. Malware indicators: suspicious process/file naming and execution patterns ----
json LogAnalyzer::detectMalwareIndicators(const json& entries) const {
    std::vector<Finding> findings;
    std::map<std::string, int> processSpawnCount;
    for (const auto& e : entries) {
        std::string proc = getStr(e, "processName");
        std::string filePath = getStr(e, "filePath");
        std::string cmd = getStr(e, "commandLine");

        if (!proc.empty()) processSpawnCount[proc]++;

        // Double-extension masquerading, e.g. invoice.pdf.exe
        auto lastDot = filePath.find_last_of('.');
        if (lastDot != std::string::npos) {
            auto secondLastDot = filePath.find_last_of('.', lastDot - 1);
            if (secondLastDot != std::string::npos) {
                std::string ext = filePath.substr(lastDot + 1);
                if (ext == "exe" || ext == "scr" || ext == "bat" || ext == "js" || ext == "vbs") {
                    findings.push_back({ "double_extension_masquerade",
                        "File \"" + filePath + "\" uses a double extension often used to disguise an executable as a document/media file",
                        30, "malware" });
                }
            }
        }

        // Execution from a temp/download directory (common dropper behaviour)
        if (!proc.empty() && (filePath.find("/tmp/") != std::string::npos ||
                               filePath.find("\\Temp\\") != std::string::npos ||
                               filePath.find("\\AppData\\Local\\Temp") != std::string::npos ||
                               filePath.find("/Downloads/") != std::string::npos)) {
            findings.push_back({ "execution_from_temp_dir",
                "Process \"" + proc + "\" executed from a temporary/download directory, a common dropper/malware behaviour pattern",
                20, "malware" });
        }

        // Obfuscated/encoded command-line invocation (common in fileless malware / LOLBins abuse)
        if (!cmd.empty() && (cmd.find("-enc") != std::string::npos || cmd.find("FromBase64String") != std::string::npos ||
                              cmd.find("-EncodedCommand") != std::string::npos || cmd.find("iex(") != std::string::npos ||
                              cmd.find("IEX (") != std::string::npos)) {
            findings.push_back({ "obfuscated_command_execution",
                "Command line contains base64/encoded execution patterns commonly used by fileless malware to evade detection",
                35, "malware" });
        }
    }
    for (const auto& [proc, count] : processSpawnCount) {
        if (count >= 20) {
            findings.push_back({ "rapid_process_spawning",
                "Process \"" + proc + "\" spawned " + std::to_string(count) + " times in the log window, consistent with a fork-bomb or automated malicious script",
                25, "malware" });
        }
    }
    return toFindingsJson(findings);
}

json LogAnalyzer::analyze(const json& logEntries) const {
    json entries = logEntries.is_array() ? logEntries : json::array();

    json portScan = detectPortScan(entries);
    json apiAbuse = detectApiAbuse(entries);
    json exfiltration = detectDataExfiltration(entries);
    json insiderThreat = detectInsiderThreat(entries);
    json malware = detectMalwareIndicators(entries);

    std::vector<json> allFindingArrays = { portScan, apiAbuse, exfiltration, insiderThreat, malware };
    json allFindings = json::array();
    int totalWeight = 0;
    int maxSingle = 0;
    for (const auto& arr : allFindingArrays) {
        for (const auto& f : arr) {
            allFindings.push_back(f);
            int w = f.value("weight", 0);
            totalWeight += w;
            if (w > maxSingle) maxSingle = w;
        }
    }
    // Same fusion philosophy as risk_scorer.cpp: lean toward the strongest
    // single signal so one severe indicator isn't diluted by many weak ones,
    // while still letting a high count of independent findings raise the floor.
    int aggregateScore = std::min(100, (int)(0.6 * maxSingle + 0.4 * std::min(100, totalWeight / 2)));

    std::string riskLevel;
    if (aggregateScore >= 80) riskLevel = "Critical";
    else if (aggregateScore >= 55) riskLevel = "High";
    else if (aggregateScore >= 30) riskLevel = "Medium";
    else if (aggregateScore >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    return json{
        {"score", aggregateScore},
        {"riskLevel", riskLevel},
        {"findings", allFindings},
        {"categoryBreakdown", {
            {"network_threat", portScan},
            {"api_abuse", apiAbuse},
            {"data_exfiltration", exfiltration},
            {"insider_threat", insiderThreat},
            {"malware", malware}
        }},
        {"entriesAnalyzed", entries.size()}
    };
}

} // namespace cyberguard
