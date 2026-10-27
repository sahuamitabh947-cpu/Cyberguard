#include "httplib.h"
#include "json.hpp"
#include "url_analyzer.h"
#include "text_analyzer.h"
#include "anomaly_detector.h"
#include "image_forensics.h"
#include "audio_forensics.h"
#include "log_analyzer.h"
#include "risk_scorer.h"
#include "model_registry.h"
#include "url_parser.h"
#include "features/media_features.h"
#include "nids/nids_engine.h"
#include "nids/live_capture.h"
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

using json = nlohmann::json;
using namespace cyberguard;

static void setCors(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, x-engine-key");
}

static std::string envOr(const char* k, const std::string& def) {
    const char* v = std::getenv(k);
    return v && *v ? v : def;
}

static std::string base64Decode(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(chars[i])] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back(static_cast<char>((val >> valb) & 0xFF)); valb -= 8; }
    }
    return out;
}

static void loadResources() {
    std::string psl = envOr("PSL_PATH", "data/public_suffix_list.dat");
    if (PublicSuffixList::instance().load(psl)) std::cout << "[psl] loaded public suffix list from " << psl << "\n";
    else std::cerr << "[psl] " << psl << " not found - using built-in suffix fallback\n";
    ModelRegistry::instance().loadAll(envOr("MODELS_DIR", "models"));
}

static int runSensor(int argc, char** argv) {
    nids::LiveOptions opt;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return i + 1 < argc ? std::string(argv[++i]) : std::string(); };
        if (a == "--iface") opt.iface = next();
        else if (a == "--bpf") opt.bpf = next();
        else if (a == "--report") opt.reportUrl = next();
        else if (a == "--key") opt.reportKey = next();
        else if (a == "--window") opt.windowSeconds = std::atoi(next().c_str());
        else if (a == "--interval") opt.analysisInterval = std::atoi(next().c_str());
        else if (a == "--name") opt.sensorName = next();
    }
    if (opt.reportKey.empty()) opt.reportKey = envOr("ENGINE_KEY", "");
    if (opt.reportUrl.empty()) opt.reportUrl = envOr("SENSOR_REPORT_URL", "");
    if (opt.iface.empty()) opt.iface = envOr("NIDS_IFACE", "");
    if (opt.bpf.empty()) opt.bpf = envOr("NIDS_BPF", "not port 4000 and not port 5050 and not port 5051 and not port 5432");
    loadResources();
    auto r = nids::LiveCapture::instance().start(opt);
    std::cout << "[sensor] " << r.dump() << std::endl;
    if (!r.value("started", false)) return 1;
    // Status endpoint for the sensor itself.
    httplib::Server svr;
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        setCors(res);
        res.set_content(json{{"status", "ok"}, {"service", "cyberguard-nids-sensor"}}.dump(), "application/json");
    });
    svr.Get("/nids/live/status", [](const httplib::Request&, httplib::Response& res) {
        setCors(res);
        res.set_content(nids::LiveCapture::instance().status().dump(), "application/json");
    });
    int port = std::atoi(envOr("SENSOR_PORT", "5051").c_str());
    std::cout << "[sensor] status endpoint on port " << port << std::endl;
    svr.listen("0.0.0.0", port);
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--sensor") return runSensor(argc, argv);

    httplib::Server svr;
    svr.set_payload_max_length(250ull * 1024 * 1024);
    svr.set_read_timeout(120, 0);
    svr.set_write_timeout(120, 0);
    UrlAnalyzer urlAnalyzer;
    TextAnalyzer textAnalyzer;
    AnomalyDetector anomalyDetector;
    ImageForensics imageForensics;
    AudioForensics audioForensics;
    LogAnalyzer logAnalyzer;
    RiskScorer riskScorer;
    auto& models = ModelRegistry::instance();
    loadResources();

    const char* portEnv = std::getenv("ENGINE_PORT");
    int port = portEnv ? std::atoi(portEnv) : 5050;
    const char* engineKeyEnv = std::getenv("ENGINE_KEY");
    std::string engineKey = engineKeyEnv ? engineKeyEnv : "";

    auto authOk = [&](const httplib::Request& req) {
        if (engineKey.empty()) return true; // no key configured -> open (dev mode)
        auto it = req.headers.find("x-engine-key");
        return it != req.headers.end() && it->second == engineKey;
    };
    auto guarded = [&](auto handler) {
        return [&, handler](const httplib::Request& req, httplib::Response& res) {
            setCors(res);
            if (!authOk(req)) { res.status = 401; res.set_content(json{{"error", "unauthorized"}}.dump(), "application/json"); return; }
            try {
                res.set_content(handler(req).dump(), "application/json");
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(json{{"error", e.what()}}.dump(), "application/json");
            }
        };
    };

    svr.Options(R"(/.*)", [](const httplib::Request&, httplib::Response& res) { setCors(res); });

    svr.Get("/health", [&](const httplib::Request&, httplib::Response& res) {
        setCors(res);
        json loaded = json::array();
        const json cards = models.modelCards();  // keep alive while iterating
        for (auto it = cards.begin(); it != cards.end(); ++it) loaded.push_back(it.key());
        res.set_content(json{{"status", "ok"}, {"service", "cyberguard-detection-engine"}, {"modelsLoaded", loaded},
                             {"livePcapSupported", nids::LiveCapture::supported()},
                             {"publicSuffixList", PublicSuffixList::instance().loaded()}}.dump(), "application/json");
    });

    // POST /analyze/url  { "url": "..." }
    svr.Post("/analyze/url", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        std::string url = body.value("url", "");
        json result = urlAnalyzer.analyze(url);
        json ml = models.predictUrl(url);
        // A lexical model cannot verify domain ownership: words like "signin" or
        // "banking" are normal on a bank's own site. When the registrable domain
        // is a verified official brand domain (and no structural trick such as
        // '@' userinfo or an encoded IP is present), cap the ML score.
        if (ml.value("available", false) && result.value("trustedBrandDomain", false)) {
            bool structural = false;
            for (auto& f : result["findings"])
                if (f["indicator"] == "userinfo_at_trick" || f["indicator"] == "obfuscated_ip_host") structural = true;
            if (!structural && ml["probability"].get<double>() > 0.2) {
                ml["rawProbability"] = ml["probability"];
                ml["probability"] = 0.2;
                ml["score"] = 20;
                ml["riskLevel"] = "Safe";
                ml["adjustment"] = "Registered domain is a verified official brand domain; lexical ML score capped (the model sees words like 'signin'/'banking' but cannot verify ownership).";
            }
        }
        result["ml"] = ml;
        return result;
    }));

    // POST /analyze/text  { "text": "...", "claimedSender": "..." }
    svr.Post("/analyze/text", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        std::string text = body.value("text", "");
        std::string sender = body.value("claimedSender", "");
        json result = textAnalyzer.analyze(text, sender);
        result["ml"] = models.predictText(text);
        return result;
    }));

    // POST /analyze/login  { userId, ipAddress, deviceFingerprint, latitude, longitude,
    //                        hourOfDay, failedAttemptsLast15Min, isKnownDevice,
    //                        lastKnownLatitude, lastKnownLongitude, minutesSinceLastLogin,
    //                        avgLoginHour, loginHourStdDev }
    svr.Post("/analyze/login", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        AnomalyDetector::LoginEvent ev;
        ev.userId = body.value("userId", "");
        ev.ipAddress = body.value("ipAddress", "");
        ev.deviceFingerprint = body.value("deviceFingerprint", "");
        ev.latitude = body.value("latitude", 0.0);
        ev.longitude = body.value("longitude", 0.0);
        ev.hourOfDay = body.value("hourOfDay", 12);
        ev.failedAttemptsLast15Min = body.value("failedAttemptsLast15Min", 0);
        ev.isKnownDevice = body.value("isKnownDevice", false);
        ev.lastKnownLatitude = body.value("lastKnownLatitude", ev.latitude);
        ev.lastKnownLongitude = body.value("lastKnownLongitude", ev.longitude);
        ev.minutesSinceLastLogin = body.value("minutesSinceLastLogin", 999999.0);
        ev.avgLoginHour = body.value("avgLoginHour", 13.0);
        ev.loginHourStdDev = body.value("loginHourStdDev", 4.0);
        json result = anomalyDetector.analyze(ev);
        features::LoginFeatureInput in;
        in.hourOfDay = ev.hourOfDay;
        in.failedAttempts15Min = ev.failedAttemptsLast15Min;
        in.knownDevice = ev.isKnownDevice;
        in.distanceKm = result.value("distanceKm", 0.0);
        in.minutesSinceLast = std::min(ev.minutesSinceLastLogin, 60.0 * 24 * 30);
        in.avgLoginHour = ev.avgLoginHour;
        in.loginHourStd = ev.loginHourStdDev;
        result["ml"] = models.predictLogin(in);
        return result;
    }));

    // POST /analyze/image  { "imageBase64": "..." }
    svr.Post("/analyze/image", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        std::string b64 = body.value("imageBase64", "");
        json result = imageForensics.analyze(b64, true);
        features::RgbImage img;
        if (features::decodeImage(base64Decode(b64), img)) result["ml"] = models.predictImage(img);
        else result["ml"] = {{"available", false}, {"reason", "image could not be decoded (JPEG/PNG/BMP/TGA supported)"}};
        return result;
    }));

    // POST /analyze/audio  { "audioBase64": "..." }  (WAV; other formats are converted by the backend)
    svr.Post("/analyze/audio", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        std::string b64 = body.value("audioBase64", "");
        json result = audioForensics.analyze(b64, true);
        std::vector<float> x;
        int sr = 16000;
        if (features::decodeWav(base64Decode(b64), x, sr)) result["ml"] = models.predictAudio(features::resampleLinear(x, sr, 16000));
        else result["ml"] = {{"available", false}, {"reason", "ML audio model needs WAV input"}};
        return result;
    }));

    // POST /analyze/logs  { "entries": [ {timestamp, sourceIp, userId, eventType, ...}, ... ] }
    svr.Post("/analyze/logs", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        json entries = body.value("entries", json::array());
        json result = logAnalyzer.analyze(entries);
        result["ml"] = models.predictLogEntities(entries);
        return result;
    }));

    // POST /analyze/pcap   raw .pcap / .pcapng bytes (Content-Type: application/octet-stream)
    svr.Post("/analyze/pcap", guarded([&](const httplib::Request& req) {
        std::string name = req.has_param("name") ? req.get_param_value("name") : "upload.pcap";
        return nids::analyzeCaptureBytes(req.body, "file:" + name);
    }));

    // Live capture (libpcap)
    svr.Get("/nids/interfaces", guarded([&](const httplib::Request&) { return nids::LiveCapture::instance().interfaces(); }));
    svr.Post("/nids/live/start", guarded([&](const httplib::Request& req) {
        json body = req.body.empty() ? json::object() : json::parse(req.body);
        nids::LiveOptions opt;
        opt.iface = body.value("iface", "");
        opt.bpf = body.value("bpf", std::string("not port 4000 and not port 5050 and not port 5432"));
        opt.windowSeconds = body.value("windowSeconds", 120);
        opt.analysisInterval = body.value("intervalSeconds", 10);
        return nids::LiveCapture::instance().start(opt);
    }));
    svr.Post("/nids/live/stop", guarded([&](const httplib::Request&) { return nids::LiveCapture::instance().stop(); }));
    svr.Get("/nids/live/status", guarded([&](const httplib::Request&) { return nids::LiveCapture::instance().status(); }));

    // Model cards (metadata + evaluation metrics, no weights)
    svr.Get("/ml/models", guarded([&](const httplib::Request&) { return models.modelCards(); }));
    // Retrain the login anomaly model from this deployment's own history
    svr.Post("/ml/train/login", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        return models.retrainLogin(body.value("events", json::array()));
    }));

    // POST /fuse  { "components": [ {source, score, weight}, ... ], "findings": [...] }
    svr.Post("/fuse", guarded([&](const httplib::Request& req) {
        auto body = json::parse(req.body);
        std::vector<json> components;
        for (auto& c : body.value("components", json::array())) components.push_back(c);
        json findings = body.value("findings", json::array());
        return riskScorer.fuse(components, findings);
    }));

    std::cout << "CyberGuard detection engine listening on port " << port << std::endl;
    svr.listen("0.0.0.0", port);
    return 0;
}
