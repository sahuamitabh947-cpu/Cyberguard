#pragma once
// Behavioural features for the unsupervised Isolation Forest models:
//   * login events  (account takeover / credential theft)
//   * per-entity aggregates of log batches (malware, API abuse,
//     exfiltration, insider threat)
#include <string>
#include <utility>
#include <vector>
#include "json.hpp"

namespace cyberguard::features {

struct LoginFeatureInput {
    int hourOfDay = 12;
    int failedAttempts15Min = 0;
    bool knownDevice = true;
    double distanceKm = 0;
    double minutesSinceLast = 1440;
    double avgLoginHour = 13;
    double loginHourStd = 4;
};

const std::vector<std::string>& loginFeatureNames();
std::vector<float> loginFeatures(const LoginFeatureInput& in);

const std::vector<std::string>& logEntityFeatureNames();
// Returns (entity id, feature vector) per user/source IP found in the batch.
std::vector<std::pair<std::string, std::vector<float>>> logEntityFeatures(const nlohmann::json& entries);

}  // namespace cyberguard::features
