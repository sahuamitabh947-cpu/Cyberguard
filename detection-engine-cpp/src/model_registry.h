#pragma once
// Loads every trained model from MODELS_DIR at start-up and serves
// predictions with per-prediction explanations. Missing models degrade
// gracefully (the rule engines keep working).
#include <mutex>
#include <string>
#include <vector>

#include "features/behavior_features.h"
#include "features/media_features.h"
#include "features/nids_features.h"
#include "json.hpp"
#include "ml/linear_models.h"
#include "ml/text_vectorizer.h"
#include "ml/tree_models.h"

namespace cyberguard {

using json = nlohmann::json;

class ModelRegistry {
public:
    static ModelRegistry& instance();
    void loadAll(const std::string& dir);

    json predictText(const std::string& text) const;
    json predictUrl(const std::string& url) const;
    json predictLogin(const features::LoginFeatureInput& in) const;
    json predictLogEntities(const json& entries) const;
    // Scores connection records in place; returns per-record predictions.
    json predictNids(const std::vector<features::ConnRecord>& conns) const;
    json predictImage(const features::RgbImage& img) const;
    json predictAudio(const std::vector<float>& samples16k) const;

    // Retrain the login Isolation Forest from real history (unsupervised).
    json retrainLogin(const json& events);

    json modelCards() const;
    bool has(const std::string& name) const;

private:
    std::string dir_;
    mutable std::mutex mu_;
    json cards_ = json::object();

    bool textLoaded = false;
    ml::TextVectorizer textVec;
    ml::LogisticRegression textLr;
    ml::MultinomialNB textNb;
    double textWLr = 1.0;

    bool urlLoaded = false;
    ml::GradientBoostedTrees urlGb;
    ml::TextVectorizer urlCharVec;
    ml::LogisticRegression urlCharLr;
    double urlWGb = 0.6;

    bool nidsLoaded = false;
    ml::GradientBoostedTrees nidsGb;
    ml::RandomForest nidsRf;
    ml::IsolationForest nidsIso;

    bool loginLoaded = false;
    ml::IsolationForest loginIso;
    bool logsLoaded = false;
    ml::IsolationForest logsIso;

    bool imageLoaded = false;
    ml::GradientBoostedTrees imageGlobal, imageBlock, imageStack;

    bool audioLoaded = false;
    ml::GradientBoostedTrees audioGb;
};

}  // namespace cyberguard
