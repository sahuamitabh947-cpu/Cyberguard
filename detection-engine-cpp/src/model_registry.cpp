#include "model_registry.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>

#include "features/url_features.h"
#include "ml/image_stack.h"

namespace fs = std::filesystem;

namespace cyberguard {

ModelRegistry& ModelRegistry::instance() {
    static ModelRegistry r;
    return r;
}

static bool readJson(const std::string& path, json& out) {
    std::ifstream in(path);
    if (!in) return false;
    try {
        in >> out;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[models] failed to parse " << path << ": " << e.what() << "\n";
        return false;
    }
}

static json cardOf(const json& m) {
    json c;
    for (auto k : {"task", "algorithm", "dataset", "metrics", "trainedAt", "featureImportance", "topMaliciousTerms", "engine", "classes"})
        if (m.contains(k)) c[k] = m[k];
    return c;
}

static std::string riskFromProb(double p) {
    if (p >= 0.9) return "Critical";
    if (p >= 0.75) return "High";
    if (p >= 0.5) return "Medium";
    if (p >= 0.25) return "Low";
    return "Safe";
}

static json topFeatures(const std::vector<double>& contrib, const std::vector<std::string>& names, const float* x, size_t k,
                        bool positiveOnly = true) {
    std::vector<size_t> idx(contrib.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return contrib[a] > contrib[b]; });
    json out = json::array();
    for (size_t i : idx) {
        if (out.size() >= k) break;
        if (positiveOnly && contrib[i] <= 0) break;
        out.push_back({{"feature", i < names.size() ? names[i] : std::to_string(i)},
                       {"value", x ? x[i] : 0.0f},
                       {"contribution", std::round(contrib[i] * 1000) / 1000}});
    }
    return out;
}

void ModelRegistry::loadAll(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mu_);
    dir_ = dir;
    json m;
    auto load = [&](const std::string& name, auto fn) {
        if (!readJson(dir + "/" + name + ".json", m)) {
            std::cerr << "[models] " << name << ": not found in " << dir << " (rule engine only)\n";
            return;
        }
        try {
            fn(m);
            cards_[name] = cardOf(m);
            cards_[name]["loaded"] = true;
            std::cout << "[models] loaded " << name << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[models] " << name << " invalid: " << e.what() << "\n";
        }
    };
    load("phishing_text", [&](const json& j) {
        textVec = ml::TextVectorizer::fromJson(j.at("vectorizer"));
        textLr = ml::LogisticRegression::fromJson(j.at("logisticRegression"));
        textNb = ml::MultinomialNB::fromJson(j.at("naiveBayes"));
        textWLr = j.at("ensembleWeights")[0].get<double>();
        textLoaded = true;
    });
    load("url_model", [&](const json& j) {
        urlGb = ml::GradientBoostedTrees::fromJson(j.at("gbdt"));
        urlCharVec = ml::TextVectorizer::fromJson(j.at("charVectorizer"));
        urlCharLr = ml::LogisticRegression::fromJson(j.at("charLogisticRegression"));
        urlWGb = j.at("ensembleWeights")[0].get<double>();
        urlLoaded = true;
    });
    load("nids_model", [&](const json& j) {
        nidsGb = ml::GradientBoostedTrees::fromJson(j.at("gbdt"));
        nidsRf = ml::RandomForest::fromJson(j.at("randomForest"));
        nidsIso = ml::IsolationForest::fromJson(j.at("isolationForest"));
        nidsLoaded = true;
    });
    load("login_anomaly", [&](const json& j) { loginIso = ml::IsolationForest::fromJson(j.at("isolationForest")); loginLoaded = true; });
    load("log_anomaly", [&](const json& j) { logsIso = ml::IsolationForest::fromJson(j.at("isolationForest")); logsLoaded = true; });
    load("image_manipulation", [&](const json& j) {
        imageGlobal = ml::GradientBoostedTrees::fromJson(j.at("gbdt"));
        imageBlock = ml::GradientBoostedTrees::fromJson(j.at("blockGbdt"));
        imageStack = ml::GradientBoostedTrees::fromJson(j.at("stackGbdt"));
        imageLoaded = true;
    });
    load("audio_deepfake", [&](const json& j) { audioGb = ml::GradientBoostedTrees::fromJson(j.at("gbdt")); audioLoaded = true; });
}

bool ModelRegistry::has(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mu_);
    return cards_.contains(name) && cards_[name].value("loaded", false);
}

json ModelRegistry::modelCards() const {
    std::lock_guard<std::mutex> lock(mu_);
    return cards_;
}

// ----------------------------------------------------------------- text --
json ModelRegistry::predictText(const std::string& text) const {
    if (!textLoaded) return json{{"available", false}};
    auto x = textVec.transform(text);
    double pLr = textLr.predictProba(x);
    double pNb = textNb.predictProba(textVec.counts(text))[1];
    double p = textWLr * pLr + (1 - textWLr) * pNb;
    json terms = json::array();
    for (auto& [idx, c] : textLr.topContributions(x, 12)) {
        if (c <= 0) continue;
        terms.push_back({{"term", textVec.termName(idx)}, {"weight", std::round(c * 1000) / 1000}});
        if (terms.size() >= 6) break;
    }
    return json{{"available", true},
                {"model", "phishing_text"},
                {"algorithm", "TF-IDF + Logistic Regression (+ Naive Bayes)"},
                {"probability", p},
                {"score", static_cast<int>(std::round(p * 100))},
                {"riskLevel", riskFromProb(p)},
                {"components", {{"logisticRegression", pLr}, {"naiveBayes", pNb}}},
                {"topIndicativeTerms", terms}};
}

// ------------------------------------------------------------------ url --
json ModelRegistry::predictUrl(const std::string& url) const {
    if (!urlLoaded) return json{{"available", false}};
    auto f = features::urlFeatures(url);
    double pGb = urlGb.predictProba(f.data());
    double pLr = urlCharLr.predictProba(urlCharVec.transform(features::canonicalUrlForModel(url)));
    double p = urlWGb * pGb + (1 - urlWGb) * pLr;
    auto contrib = urlGb.contributions(f.data(), f.size());
    return json{{"available", true},
                {"model", "url_model"},
                {"algorithm", "Gradient Boosted Trees + char n-gram Logistic Regression"},
                {"probability", p},
                {"score", static_cast<int>(std::round(p * 100))},
                {"riskLevel", riskFromProb(p)},
                {"components", {{"gradientBoostedTrees", pGb}, {"charNgramLogReg", pLr}}},
                {"schemeInvariant", true},
                {"topFeatures", topFeatures(contrib, features::urlFeatureNames(), f.data(), 6)}};
}

// ---------------------------------------------------------------- login --
json ModelRegistry::predictLogin(const features::LoginFeatureInput& in) const {
    if (!loginLoaded) return json{{"available", false}};
    auto f = features::loginFeatures(in);
    double s;
    int worst = -1;
    double env;
    {
        std::lock_guard<std::mutex> lock(mu_);
        s = loginIso.score(f.data());
        env = loginIso.envelopeScore(f.data(), &worst);
    }
    double p = std::clamp((s - loginIso.threshold) / 0.15 * 0.5 + 0.5, 0.0, 1.0);
    auto contrib = loginIso.isolationContributions(f.data(), f.size());
    json out = {{"available", true},
                {"model", "login_anomaly"},
                {"algorithm", "Isolation Forest + robust envelope"},
                {"anomalyScore", s},
                {"threshold", loginIso.threshold},
                {"isAnomaly", s >= loginIso.threshold},
                {"probability", p},
                {"score", static_cast<int>(std::round(p * 100))},
                {"riskLevel", s >= loginIso.threshold ? riskFromProb(std::max(p, 0.5)) : "Safe"},
                {"topFeatures", topFeatures(contrib, features::loginFeatureNames(), f.data(), 4)}};
    if (worst >= 0 && env > 0) out["outOfRangeFeature"] = features::loginFeatureNames()[worst];
    return out;
}

json ModelRegistry::retrainLogin(const json& events) {
    ml::DenseDataset ds;
    ds.featureNames = features::loginFeatureNames();
    for (auto& e : events) {
        features::LoginFeatureInput in;
        in.hourOfDay = e.value("hourOfDay", 12);
        in.failedAttempts15Min = e.value("failedAttemptsLast15Min", 0);
        in.knownDevice = e.value("isKnownDevice", true);
        in.distanceKm = e.value("distanceKm", 0.0);
        in.minutesSinceLast = e.value("minutesSinceLastLogin", 1440.0);
        in.avgLoginHour = e.value("avgLoginHour", 13.0);
        in.loginHourStd = e.value("loginHourStdDev", 4.0);
        ds.addRow(features::loginFeatures(in), 0);
    }
    if (ds.n < 200) return json{{"retrained", false}, {"reason", "need at least 200 successful logins, have " + std::to_string(ds.n)}};
    std::vector<size_t> all(ds.n);
    std::iota(all.begin(), all.end(), 0);
    ml::IsolationForest iso;
    ml::IsolationForest::Params p;
    p.nTrees = 200; p.sampleSize = 256; p.contamination = 0.02; p.useEnvelope = true;
    iso.fit(ds, all, p);
    std::lock_guard<std::mutex> lock(mu_);
    loginIso = iso;
    loginLoaded = true;
    json file;
    readJson(dir_ + "/login_anomaly.json", file);
    file["isolationForest"] = iso.toJson();
    file["dataset"] = {{"name", "Retrained on this deployment's own successful logins"}, {"trainSamples", ds.n}};
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    file["trainedAt"] = buf;
    std::ofstream(dir_ + "/login_anomaly.json") << file.dump();
    cards_["login_anomaly"] = cardOf(file);
    cards_["login_anomaly"]["loaded"] = true;
    return json{{"retrained", true}, {"samples", ds.n}, {"threshold", iso.threshold}};
}

// ----------------------------------------------------------------- logs --
json ModelRegistry::predictLogEntities(const json& entries) const {
    if (!logsLoaded) return json{{"available", false}};
    json ents = json::array();
    double maxP = 0;
    for (auto& [id, f] : features::logEntityFeatures(entries)) {
        double s = logsIso.score(f.data());
        int worst = -1;
        logsIso.envelopeScore(f.data(), &worst);
        double p = std::clamp((s - logsIso.threshold) / 0.15 * 0.5 + 0.5, 0.0, 1.0);
        maxP = std::max(maxP, s >= logsIso.threshold ? p : 0.0);
        auto contrib = logsIso.isolationContributions(f.data(), f.size());
        json e = {{"entity", id}, {"anomalyScore", s}, {"isAnomaly", s >= logsIso.threshold},
                  {"topFeatures", topFeatures(contrib, features::logEntityFeatureNames(), f.data(), 3)}};
        if (worst >= 0) e["outOfRangeFeature"] = features::logEntityFeatureNames()[worst];
        ents.push_back(e);
    }
    std::sort(ents.begin(), ents.end(), [](const json& a, const json& b) { return a["anomalyScore"] > b["anomalyScore"]; });
    return json{{"available", true}, {"model", "log_anomaly"}, {"algorithm", "Isolation Forest + robust envelope"},
                {"threshold", logsIso.threshold}, {"probability", maxP}, {"score", static_cast<int>(std::round(maxP * 100))},
                {"entities", ents}};
}

// ----------------------------------------------------------------- NIDS --
json ModelRegistry::predictNids(const std::vector<features::ConnRecord>& conns) const {
    json out = json::array();
    if (!nidsLoaded) return out;
    const auto& classes = features::nidsClasses();
    for (auto& c : conns) {
        auto f = features::nidsFeatureVector(c);
        double pGb = nidsGb.predictProba(f.data());
        auto pr = nidsRf.predictProba(f.data());
        int cls = static_cast<int>(std::max_element(pr.begin(), pr.end()) - pr.begin());
        double iso = nidsIso.score(f.data());
        bool novel = iso >= nidsIso.threshold;
        double p = std::max(pGb, 1.0 - pr[0]) * 0.85 + (novel ? 0.15 : 0.0);
        json r = {{"attackProbability", p}, {"gbdt", pGb}, {"category", classes[cls]},
                  {"categoryProbabilities", {{"normal", pr[0]}, {"dos", pr[1]}, {"probe", pr[2]}, {"r2l", pr[3]}, {"u2r", pr[4]}}},
                  {"noveltyScore", iso}, {"novel", novel}};
        if (p >= 0.5) {
            auto contrib = nidsGb.contributions(f.data(), f.size());
            r["topFeatures"] = topFeatures(contrib, features::nidsFeatureNames(), f.data(), 4);
        }
        out.push_back(r);
    }
    return out;
}

// ---------------------------------------------------------------- image --
json ModelRegistry::predictImage(const features::RgbImage& img) const {
    if (!imageLoaded) return json{{"available", false}};
    auto g = features::imageFeatures(img);
    float gS = static_cast<float>(imageGlobal.predictProba(g.data()));
    auto blocks = features::imageBlockFeatures(img);
    std::vector<double> bs;
    for (auto& b : blocks) bs.push_back(imageBlock.predictProba(b.f.data()));
    auto agg = ml::aggregateImageBlocks(bs, blocks, gS);
    double p = imageStack.predictProba(agg.data());
    std::vector<size_t> idx(bs.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return bs[a] > bs[b]; });
    json hot = json::array();
    for (size_t k = 0; k < idx.size() && hot.size() < 5; ++k)
        if (bs[idx[k]] >= 0.7) hot.push_back({{"x", blocks[idx[k]].x}, {"y", blocks[idx[k]].y}, {"size", blocks[idx[k]].size}, {"score", bs[idx[k]]}});
    auto contrib = imageGlobal.contributions(g.data(), g.size());
    int analysedW = std::min(img.w, 512), analysedH = std::min(img.h, 512);
    return json{{"available", true},
                {"model", "image_manipulation"},
                {"algorithm", "Block-level + global Gradient Boosted Trees (stacked)"},
                {"experimental", true},
                {"probability", p},
                {"score", static_cast<int>(std::round(p * 100))},
                {"riskLevel", riskFromProb(p)},
                {"components", {{"globalModel", gS}, {"blockTop2Mean", agg[2]}, {"best2x2Region", agg[7]}}},
                {"suspiciousBlocks", hot},
                {"analysedRegion", {{"width", analysedW}, {"height", analysedH}, {"note", "centre crop (max 512px) of the uploaded image"}}},
                {"topGlobalFeatures", topFeatures(contrib, features::imageFeatureNames(), g.data(), 4)}};
}

// ---------------------------------------------------------------- audio --
json ModelRegistry::predictAudio(const std::vector<float>& x) const {
    if (!audioLoaded) return json{{"available", false}};
    // Score 2-second windows and aggregate (mean of top half).
    const size_t seg = 32000, hop = 16000;
    std::vector<double> ps;
    std::vector<float> firstFeat;
    if (x.size() <= seg) {
        std::vector<float> w(x);
        w.resize(seg, 0.0f);
        firstFeat = features::audioFeatures(w);
        ps.push_back(audioGb.predictProba(firstFeat.data()));
    } else {
        for (size_t s = 0; s + seg <= x.size() && ps.size() < 60; s += hop) {
            std::vector<float> w(x.begin() + s, x.begin() + s + seg);
            auto f = features::audioFeatures(w);
            if (firstFeat.empty()) firstFeat = f;
            ps.push_back(audioGb.predictProba(f.data()));
        }
    }
    std::vector<double> sorted(ps);
    std::sort(sorted.rbegin(), sorted.rend());
    size_t k = std::max<size_t>(1, sorted.size() / 2);
    double p = std::accumulate(sorted.begin(), sorted.begin() + k, 0.0) / k;
    auto contrib = audioGb.contributions(firstFeat.data(), firstFeat.size());
    return json{{"available", true},
                {"model", "audio_deepfake"},
                {"algorithm", "Gradient Boosted Trees on MFCC + spectral features"},
                {"probability", p},
                {"score", static_cast<int>(std::round(p * 100))},
                {"riskLevel", riskFromProb(p)},
                {"windowsAnalysed", ps.size()},
                {"windowProbabilities", ps},
                {"topFeatures", topFeatures(contrib, features::audioFeatureNames(), firstFeat.data(), 4)}};
}

}  // namespace cyberguard
