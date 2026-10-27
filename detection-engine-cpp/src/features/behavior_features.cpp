#include "behavior_features.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace cyberguard::features {

const std::vector<std::string>& loginFeatureNames() {
    static const std::vector<std::string> n = {"hour_sin", "hour_cos", "hour_deviation_z", "failed_attempts_log",
                                               "new_device", "distance_km_log", "implied_speed_kmh_log",
                                               "minutes_since_last_log"};
    return n;
}

std::vector<float> loginFeatures(const LoginFeatureInput& in) {
    const double PI = 3.14159265358979;
    double diff = std::fabs(in.hourOfDay - in.avgLoginHour);
    diff = std::min(diff, 24.0 - diff);
    double z = diff / std::max(0.5, in.loginHourStd);
    double minutes = std::max(1.0, in.minutesSinceLast);
    double speed = in.distanceKm / minutes * 60.0;
    return {static_cast<float>(std::sin(2 * PI * in.hourOfDay / 24.0)),
            static_cast<float>(std::cos(2 * PI * in.hourOfDay / 24.0)),
            static_cast<float>(std::min(z, 12.0)),
            static_cast<float>(std::log1p(std::max(0, in.failedAttempts15Min))),
            in.knownDevice ? 0.0f : 1.0f,
            static_cast<float>(std::log1p(std::max(0.0, in.distanceKm))),
            static_cast<float>(std::log1p(std::max(0.0, speed))),
            static_cast<float>(std::log1p(minutes))};
}

const std::vector<std::string>& logEntityFeatureNames() {
    static const std::vector<std::string> n = {
        "events_log", "distinct_dst_ports", "distinct_endpoints", "max_requests_per_endpoint_log", "error_ratio",
        "bytes_transferred_log", "off_hours_bulk_transfers", "sensitive_events", "distinct_files_log",
        "max_process_spawn_log", "encoded_commands", "suspicious_file_ops"};
    return n;
}

namespace {
struct Agg {
    long events = 0, errors = 0, httpReqs = 0;
    std::set<int> ports;
    std::map<std::string, long> endpoints;
    double bytes = 0;
    long offHoursBulk = 0, sensitive = 0, encoded = 0, suspiciousFile = 0;
    std::set<std::string> files;
    std::map<std::string, long> spawns;
};
std::string str(const nlohmann::json& e, const char* k) {
    return e.contains(k) && e[k].is_string() ? e[k].get<std::string>() : std::string();
}
double num(const nlohmann::json& e, const char* k, double d = 0) {
    return e.contains(k) && e[k].is_number() ? e[k].get<double>() : d;
}
}  // namespace

std::vector<std::pair<std::string, std::vector<float>>> logEntityFeatures(const nlohmann::json& entries) {
    static const std::set<std::string> sensitiveEvents = {"permission_change", "role_escalation", "mass_download",
                                                          "file_delete_bulk", "admin_access", "export_data",
                                                          "disable_logging", "access_after_termination"};
    std::map<std::string, Agg> aggs;
    if (!entries.is_array()) return {};
    for (const auto& e : entries) {
        std::string id = str(e, "userId");
        if (id.empty()) id = str(e, "sourceIp");
        if (id.empty()) id = str(e, "processName").empty() ? "unknown" : "host";
        Agg& a = aggs[id];
        a.events++;
        if (e.contains("destinationPort")) a.ports.insert(static_cast<int>(num(e, "destinationPort")));
        std::string ep = str(e, "apiEndpoint");
        if (!ep.empty()) {
            a.endpoints[ep]++;
            a.httpReqs++;
            if (num(e, "httpStatus", 200) >= 400) a.errors++;
        }
        double bytes = num(e, "bytesTransferred");
        a.bytes += bytes;
        int hour = static_cast<int>(num(e, "hourOfDay", 12));
        if (bytes > 100.0 * 1024 * 1024 && (hour < 6 || hour > 22)) a.offHoursBulk++;
        if (sensitiveEvents.count(str(e, "eventType"))) a.sensitive++;
        std::string fp = str(e, "filePath");
        if (!fp.empty()) {
            a.files.insert(fp);
            std::string lower = fp;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            auto dot = lower.rfind('.');
            bool doubleExt = dot != std::string::npos && lower.rfind('.', dot - 1) != std::string::npos &&
                             (lower.substr(dot) == ".exe" || lower.substr(dot) == ".scr" || lower.substr(dot) == ".js" ||
                              lower.substr(dot) == ".vbs" || lower.substr(dot) == ".bat");
            bool tempExec = lower.find("/tmp/") != std::string::npos || lower.find("\\temp\\") != std::string::npos ||
                            lower.find("/downloads/") != std::string::npos;
            if (doubleExt || (tempExec && !str(e, "processName").empty())) a.suspiciousFile++;
        }
        std::string proc = str(e, "processName");
        if (!proc.empty()) a.spawns[proc]++;
        std::string cmd = str(e, "commandLine");
        if (cmd.find("-enc") != std::string::npos || cmd.find("FromBase64String") != std::string::npos ||
            cmd.find("-EncodedCommand") != std::string::npos || cmd.find("iex(") != std::string::npos ||
            cmd.find("IEX (") != std::string::npos)
            a.encoded++;
    }
    std::vector<std::pair<std::string, std::vector<float>>> out;
    for (auto& [id, a] : aggs) {
        long maxEp = 0, maxSpawn = 0;
        for (auto& [k, v] : a.endpoints) maxEp = std::max(maxEp, v);
        for (auto& [k, v] : a.spawns) maxSpawn = std::max(maxSpawn, v);
        out.push_back({id,
                       {static_cast<float>(std::log1p(a.events)), static_cast<float>(a.ports.size()),
                        static_cast<float>(a.endpoints.size()), static_cast<float>(std::log1p(maxEp)),
                        a.httpReqs ? static_cast<float>(a.errors) / a.httpReqs : 0.0f,
                        static_cast<float>(std::log1p(a.bytes / 1024.0)), static_cast<float>(a.offHoursBulk),
                        static_cast<float>(a.sensitive), static_cast<float>(std::log1p(a.files.size())),
                        static_cast<float>(std::log1p(maxSpawn)), static_cast<float>(a.encoded),
                        static_cast<float>(a.suspiciousFile)}});
    }
    return out;
}

}  // namespace cyberguard::features
