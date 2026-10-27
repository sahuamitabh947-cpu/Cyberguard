#pragma once
#include <string>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Detects abnormal authentication / account behaviour: failed login bursts,
// impossible-travel geolocation jumps, new-device logins, and off-hours access.
// This implements a lightweight hybrid rule + statistical model so it runs
// with zero training data and zero external ML dependencies, while still
// producing a genuine, explainable, per-signal risk contribution.
class AnomalyDetector {
public:
    struct LoginEvent {
        std::string userId;
        std::string ipAddress;
        std::string deviceFingerprint;
        double latitude = 0.0;
        double longitude = 0.0;
        int hourOfDay = 0;              // 0-23, local
        int failedAttemptsLast15Min = 0;
        bool isKnownDevice = false;
        double lastKnownLatitude = 0.0;
        double lastKnownLongitude = 0.0;
        double minutesSinceLastLogin = 999999.0;
        double avgLoginHour = 13.0;      // user's historical average login hour
        double loginHourStdDev = 4.0;    // user's historical std dev of login hour
    };

    json analyze(const LoginEvent& event) const;

private:
    double haversineKm(double lat1, double lon1, double lat2, double lon2) const;
};

} // namespace cyberguard
