#include "anomaly_detector.h"
#include <cmath>
#include <vector>

namespace cyberguard {

double AnomalyDetector::haversineKm(double lat1, double lon1, double lat2, double lon2) const {
    constexpr double R = 6371.0;
    auto toRad = [](double d) { return d * M_PI / 180.0; };
    double dLat = toRad(lat2 - lat1);
    double dLon = toRad(lon2 - lon1);
    double a = std::sin(dLat / 2) * std::sin(dLat / 2) +
               std::cos(toRad(lat1)) * std::cos(toRad(lat2)) *
               std::sin(dLon / 2) * std::sin(dLon / 2);
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a));
    return R * c;
}

json AnomalyDetector::analyze(const LoginEvent& e) const {
    struct Finding { std::string indicator; std::string detail; int weight; };
    std::vector<Finding> findings;
    int score = 0;

    // 1. Brute-force / credential-stuffing signal
    if (e.failedAttemptsLast15Min >= 10) {
        findings.push_back({ "brute_force_pattern", "10+ failed login attempts within 15 minutes, consistent with password spraying or credential stuffing", 40 });
        score += 40;
    } else if (e.failedAttemptsLast15Min >= 5) {
        findings.push_back({ "repeated_failed_logins", std::to_string(e.failedAttemptsLast15Min) + " failed login attempts within 15 minutes", 20 });
        score += 20;
    }

    // 2. Impossible-travel / geo-velocity signal
    double distanceKm = haversineKm(e.latitude, e.longitude, e.lastKnownLatitude, e.lastKnownLongitude);
    double minutes = std::max(e.minutesSinceLastLogin, 1.0);
    double impliedSpeedKmh = (distanceKm / minutes) * 60.0;
    if (distanceKm > 300 && impliedSpeedKmh > 900) {
        findings.push_back({ "impossible_travel", "Login location is ~" + std::to_string((int)distanceKm) +
            " km from the previous session's location, implying a travel speed of ~" + std::to_string((int)impliedSpeedKmh) +
            " km/h, which is not physically plausible", 35 });
        score += 35;
    } else if (distanceKm > 300) {
        findings.push_back({ "unusual_location", "Login originated roughly " + std::to_string((int)distanceKm) + " km from the account's last known location", 15 });
        score += 15;
    }

    // 3. New / unrecognised device
    if (!e.isKnownDevice) {
        findings.push_back({ "new_device", "Login from a device fingerprint not previously associated with this account", 15 });
        score += 15;
    }

    // 4. Off-hours access relative to the user's historical login-time distribution (z-score)
    double stdDev = e.loginHourStdDev > 0.1 ? e.loginHourStdDev : 0.1;
    double diff = std::fabs(e.hourOfDay - e.avgLoginHour);
    diff = std::min(diff, 24.0 - diff); // wrap around midnight
    double zScore = diff / stdDev;
    if (zScore > 3.0) {
        findings.push_back({ "off_hours_access", "Login hour deviates sharply (z-score " + std::to_string(zScore).substr(0,4) + ") from this account's normal activity pattern", 12 });
        score += 12;
    }

    if (score > 100) score = 100;

    std::string riskLevel;
    if (score >= 80) riskLevel = "Critical";
    else if (score >= 55) riskLevel = "High";
    else if (score >= 30) riskLevel = "Medium";
    else if (score >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    json findingsJson = json::array();
    for (const auto& f : findings) {
        findingsJson.push_back({ {"indicator", f.indicator}, {"detail", f.detail}, {"weight", f.weight} });
    }

    return json{
        {"userId", e.userId},
        {"score", score},
        {"riskLevel", riskLevel},
        {"distanceKm", distanceKm},
        {"impliedSpeedKmh", impliedSpeedKmh},
        {"findings", findingsJson}
    };
}

} // namespace cyberguard
