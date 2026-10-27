// cg_train — trains every CyberGuard ML model in C++ and writes them to
// models/*.json together with held-out evaluation metrics.
//
//   ./cg_train <datasets_dir> <models_dir> [all|text|url|nids|login|logs|image|audio]
//
// Datasets (see datasets/README.md and datasets/fetch_datasets.sh at the project root):
//   sms.tsv                  UCI SMS Spam Collection (CC BY 4.0)
//   enron_spam_data.csv      Enron-Spam (Metsis et al.), via MWiechmann/enron_spam_data
//   urls_faizann.csv         malicious/benign URLs (faizann24 on GitHub)
//   urls_phishing_recent.txt sample of Phishing.Database ACTIVE list (MIT)
//   KDDTrain.txt/KDDTest.txt NSL-KDD (UNB CIC)
//   images/originals/        public-domain photos (imageio / scikit-image)
//   audio/real, audio/tts    LibriSpeech clips (CC BY 4.0) / espeak-ng speech
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>

#include "features/behavior_features.h"
#include "features/media_features.h"
#include "features/nids_features.h"
#include "features/url_features.h"
#include "ml/image_stack.h"
#include "ml/linear_models.h"
#include "ml/ml_core.h"
#include "ml/text_vectorizer.h"
#include "ml/tree_models.h"
#include "url_parser.h"

namespace fs = std::filesystem;
using namespace cyberguard;
using namespace cyberguard::ml;
using json = nlohmann::json;

static std::string DATA, OUT;
static json SUMMARY = json::object();

static std::string nowIso() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

static std::string readFile(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static void writeModel(const std::string& name, json model) {
    model["trainedAt"] = nowIso();
    model["engine"] = "CyberGuard C++ ML (cg_train)";
    std::ofstream o(OUT + "/" + name + ".json");
    o << model.dump();
    std::cout << "  -> wrote " << OUT << "/" << name << ".json (" << fs::file_size(OUT + "/" + name + ".json") / 1024 << " KB)\n";
    json s = {{"file", name + ".json"}, {"algorithm", model["algorithm"]}, {"task", model["task"]},
              {"metrics", model["metrics"]}, {"dataset", model["dataset"]}, {"trainedAt", model["trainedAt"]}};
    SUMMARY[name] = s;
}

static void logMetrics(const std::string& label, const BinaryMetrics& m) {
    std::cout << std::fixed << std::setprecision(4) << "  [" << label << "] acc=" << m.accuracy << " prec=" << m.precision
              << " rec=" << m.recall << " f1=" << m.f1 << " auc=" << m.rocAuc << " (n=" << m.n << ")\n";
}

// Simple CSV row parser with quotes and embedded newlines handled by caller.
static bool readCsvRecord(std::istream& in, std::vector<std::string>& fields) {
    fields.clear();
    std::string field;
    bool inQuotes = false, any = false;
    char c;
    while (in.get(c)) {
        any = true;
        if (inQuotes) {
            if (c == '"') {
                if (in.peek() == '"') { field.push_back('"'); in.get(c); }
                else inQuotes = false;
            } else field.push_back(c);
        } else {
            if (c == '"') inQuotes = true;
            else if (c == ',') { fields.push_back(field); field.clear(); }
            else if (c == '\n') { fields.push_back(field); return true; }
            else if (c != '\r') field.push_back(c);
        }
    }
    if (any) { fields.push_back(field); return true; }
    return false;
}

// Cross-domain sanity set: the hand-written evaluation/dataset.json samples.
static json loadEvalSet() {
    for (auto p : {DATA + "/../cyberguard/evaluation/dataset.json", DATA + "/eval_dataset.json"})
        if (fs::exists(p)) return json::parse(readFile(p));
    return json();
}

// ================================================================= TEXT ==
static void trainText() {
    std::cout << "\n== Phishing / scam message model (TF-IDF + Logistic Regression + Naive Bayes)\n";
    std::vector<std::string> docs;
    std::vector<int> y;
    std::vector<std::string> source;
    {
        std::ifstream in(DATA + "/sms.tsv");
        std::string line;
        while (std::getline(in, line)) {
            auto tab = line.find('\t');
            if (tab == std::string::npos) continue;
            docs.push_back(line.substr(tab + 1));
            y.push_back(line.substr(0, tab) == "spam");
            source.push_back("sms");
        }
    }
    {
        std::ifstream in(DATA + "/enron_spam_data.csv", std::ios::binary);
        std::vector<std::string> f;
        readCsvRecord(in, f);  // header
        while (readCsvRecord(in, f)) {
            if (f.size() < 4) continue;
            std::string text = f[1] + "\n" + f[2];
            if (text.size() > 4000) text.resize(4000);
            docs.push_back(text);
            y.push_back(f[3] == "spam");
            source.push_back("email");
        }
    }
    std::cout << "  samples: " << docs.size() << " (positives " << std::count(y.begin(), y.end(), 1) << ")\n";
    std::vector<size_t> tr, te;
    trainTestSplit(docs.size(), 0.2, 17, tr, te, &y);

    std::vector<std::string> trDocs;
    for (auto i : tr) trDocs.push_back(docs[i]);
    TextVectorizer vec;
    TextVectorizer::Params vp;
    vp.ngramMin = 1; vp.ngramMax = 2; vp.minDf = 3; vp.maxFeatures = 50000;
    vec.fit(trDocs, vp);
    std::cout << "  vocabulary: " << vec.size() << " terms\n";

    std::vector<SparseVec> Xtr, Xte, Ctr, Cte;
    std::vector<int> ytr, yte;
    for (auto i : tr) { Xtr.push_back(vec.transform(docs[i])); Ctr.push_back(vec.counts(docs[i])); ytr.push_back(y[i]); }
    for (auto i : te) { Xte.push_back(vec.transform(docs[i])); Cte.push_back(vec.counts(docs[i])); yte.push_back(y[i]); }

    LogisticRegression lr;
    LogisticRegression::Params lp;
    lp.epochs = 6; lp.learningRate = 0.5;
    lr.fit(Xtr, ytr, vec.size(), lp);
    MultinomialNB nb;
    nb.fit(Ctr, ytr, vec.size(), 2, 0.5);

    // Choose the ensemble weight on a validation split carved from TRAIN
    // (models refit on the remaining 90%), never on the test set.
    double wLr = 0.7;
    {
        std::vector<size_t> fitIdx, valIdx;
        trainTestSplit(Xtr.size(), 0.1, 23, fitIdx, valIdx, &ytr);
        std::vector<SparseVec> Xf, Cf; std::vector<int> yf;
        for (auto i : fitIdx) { Xf.push_back(Xtr[i]); Cf.push_back(Ctr[i]); yf.push_back(ytr[i]); }
        LogisticRegression lrV; lrV.fit(Xf, yf, vec.size(), lp);
        MultinomialNB nbV; nbV.fit(Cf, yf, vec.size(), 2, 0.5);
        double bestF1 = -1;
        for (int w = 5; w <= 10; ++w) {
            std::vector<int> yv; std::vector<double> sv;
            for (auto i : valIdx) { yv.push_back(ytr[i]); sv.push_back(w / 10.0 * lrV.predictProba(Xtr[i]) + (1 - w / 10.0) * nbV.predictProba(Ctr[i])[1]); }
            double f1 = evaluateBinary(yv, sv).f1;
            if (f1 > bestF1) { bestF1 = f1; wLr = w / 10.0; }
        }
        std::cout << "  validation-selected ensemble weight: LR " << wLr << " / NB " << 1 - wLr << "\n";
    }
    std::vector<double> sLr, sNb, sEns;
    for (size_t k = 0; k < Xte.size(); ++k) {
        double a = lr.predictProba(Xte[k]), b = nb.predictProba(Cte[k])[1];
        sLr.push_back(a); sNb.push_back(b); sEns.push_back(wLr * a + (1 - wLr) * b);
    }
    auto mLr = evaluateBinary(yte, sLr), mNb = evaluateBinary(yte, sNb), mEns = evaluateBinary(yte, sEns);
    logMetrics("logreg", mLr); logMetrics("naive_bayes", mNb); logMetrics("ensemble", mEns);

    json perSource;
    for (std::string src : {"sms", "email"}) {
        std::vector<int> ys; std::vector<double> ss;
        for (size_t k = 0; k < te.size(); ++k) if (source[te[k]] == src) { ys.push_back(yte[k]); ss.push_back(sEns[k]); }
        auto m = evaluateBinary(ys, ss);
        logMetrics("ensemble/" + src, m);
        perSource[src] = m.toJson();
        std::vector<double> sl;
        for (size_t k = 0; k < te.size(); ++k) if (source[te[k]] == src) sl.push_back(sLr[k]);
        logMetrics("logreg/" + src, evaluateBinary(ys, sl));
    }
    // cross-domain: hand-written phishing set used by the earlier rule-engine evaluation
    json evalSet = loadEvalSet(), crossDomain = nullptr;
    if (!evalSet.is_null()) {
        std::vector<int> ys; std::vector<double> ss;
        for (auto& s : evalSet["textSamples"]) {
            std::string t = s["text"].get<std::string>();
            ys.push_back(s["label"] == "phishing");
            ss.push_back(wLr * lr.predictProba(vec.transform(t)) + (1 - wLr) * nb.predictProba(vec.counts(t))[1]);
        }
        auto m = evaluateBinary(ys, ss);
        logMetrics("ensemble/phishing-eval-set", m);
        crossDomain = m.toJson();
    }
    // top indicative terms for the model card
    std::vector<std::pair<double, std::string>> terms;
    for (size_t j = 0; j < vec.size(); ++j) terms.push_back({lr.w[j], vec.termName(static_cast<int>(j))});
    std::sort(terms.rbegin(), terms.rend());
    json topPos = json::array();
    for (int k = 0; k < 25; ++k) topPos.push_back(terms[k].second);

    writeModel("phishing_text", {
        {"task", "Phishing / scam / spam detection for emails, SMS and messages"},
        {"algorithm", "TF-IDF (word 1-2 grams) + Logistic Regression (AdaGrad) + Multinomial Naive Bayes, weighted ensemble (weight chosen on a validation split)"},
        {"dataset", {{"name", "UCI SMS Spam Collection + Enron-Spam"}, {"samples", docs.size()},
                     {"split", "stratified 80/20"}, {"trainSamples", tr.size()}, {"testSamples", te.size()}}},
        {"metrics", {{"ensemble", mEns.toJson()}, {"logisticRegression", mLr.toJson()}, {"naiveBayes", mNb.toJson()},
                     {"bySource", perSource}, {"handWrittenPhishingSet", crossDomain}}},
        {"topMaliciousTerms", topPos},
        {"threshold", 0.5},
        {"ensembleWeights", {wLr, 1 - wLr}},
        {"vectorizer", vec.toJson()}, {"logisticRegression", lr.toJson()}, {"naiveBayes", nb.toJson()}});
}

// ================================================================== URL ==
static void trainUrl() {
    std::cout << "\n== Malicious URL model (Gradient Boosted Trees on 42 lexical features + char n-gram Logistic Regression)\n";
    std::vector<std::string> urls;
    std::vector<int> y;
    std::set<std::string> seen;
    {
        std::ifstream in(DATA + "/urls_faizann.csv", std::ios::binary);
        std::vector<std::string> f;
        readCsvRecord(in, f);
        while (readCsvRecord(in, f)) {
            if (f.size() < 2 || f[0].empty()) continue;
            std::string c = features::canonicalUrlForModel(f[0]);
            if (!seen.insert(c).second) continue;
            urls.push_back(f[0]);
            y.push_back(f[1] == "bad");
        }
    }
    {
        std::ifstream in(DATA + "/urls_phishing_recent.txt");
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            std::string c = features::canonicalUrlForModel(line);
            if (!seen.insert(c).second) continue;
            urls.push_back(line);
            y.push_back(1);
        }
    }
    std::cout << "  unique URLs: " << urls.size() << " (malicious " << std::count(y.begin(), y.end(), 1) << ")\n";

    // Group split by registrable domain so the same site never appears in
    // both train and test (prevents memorising domains).
    std::vector<size_t> tr, te;
    for (size_t i = 0; i < urls.size(); ++i) {
        ParsedUrl u = parseUrl("http://" + features::canonicalUrlForModel(urls[i]));
        std::string key = u.registrableDomain.empty() ? u.host : u.registrableDomain;
        (std::hash<std::string>{}(key) % 5 == 0 ? te : tr).push_back(i);
    }
    std::cout << "  group split by registrable domain: train " << tr.size() << ", test " << te.size() << "\n";

    DenseDataset ds;
    ds.featureNames = features::urlFeatureNames();
    for (size_t i = 0; i < urls.size(); ++i) ds.addRow(features::urlFeatures(urls[i]), y[i]);

    GradientBoostedTrees gb;
    GradientBoostedTrees::Params gp;
    gp.nTrees = 250; gp.maxDepth = 7; gp.learningRate = 0.12; gp.minSamplesLeaf = 20;
    auto t0 = std::chrono::steady_clock::now();
    gb.fit(ds, tr, gp);
    std::cout << "  GBDT trained in " << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t0).count() << "s\n";

    // Char n-gram LR on a subsample (memory) of the training split.
    std::vector<size_t> trSub(tr);
    std::mt19937 rng(9);
    std::shuffle(trSub.begin(), trSub.end(), rng);
    if (trSub.size() > 220000) trSub.resize(220000);
    std::vector<std::string> trDocs;
    for (auto i : trSub) trDocs.push_back(features::canonicalUrlForModel(urls[i]));
    TextVectorizer cv;
    TextVectorizer::Params cp;
    cp.charMode = true; cp.ngramMin = 3; cp.ngramMax = 5; cp.minDf = 5; cp.maxFeatures = 60000;
    cv.fit(std::vector<std::string>(trDocs.begin(), trDocs.begin() + std::min<size_t>(trDocs.size(), 120000)), cp);
    std::vector<SparseVec> Xc;
    std::vector<int> yc;
    for (size_t k = 0; k < trSub.size(); ++k) { Xc.push_back(cv.transform(trDocs[k])); yc.push_back(y[trSub[k]]); }
    LogisticRegression clr;
    LogisticRegression::Params lp;
    lp.epochs = 4; lp.learningRate = 0.3;
    clr.fit(Xc, yc, cv.size(), lp);
    std::vector<SparseVec>().swap(Xc);

    std::vector<int> yte;
    std::vector<double> sGb, sLr, sEns;
    for (auto i : te) {
        double a = gb.predictProba(ds.row(i));
        double b = clr.predictProba(cv.transform(features::canonicalUrlForModel(urls[i])));
        yte.push_back(y[i]); sGb.push_back(a); sLr.push_back(b); sEns.push_back(0.6 * a + 0.4 * b);
    }
    auto mGb = evaluateBinary(yte, sGb), mLr = evaluateBinary(yte, sLr), mEns = evaluateBinary(yte, sEns);
    logMetrics("gbdt", mGb); logMetrics("char-lr", mLr); logMetrics("ensemble", mEns);

    // Scheme-invariance check: http:// vs https:// must give identical scores.
    int schemeMismatch = 0;
    for (size_t k = 0; k < 2000 && k < te.size(); ++k) {
        std::string c = features::canonicalUrlForModel(urls[te[k]]);
        auto a = features::urlFeatures("http://" + c), b = features::urlFeatures("https://www." + c);
        if (gb.predictProba(a.data()) != gb.predictProba(b.data())) schemeMismatch++;
    }
    std::cout << "  scheme-invariance check (http vs https://www.) mismatches: " << schemeMismatch << " / 2000\n";

    json evalSet = loadEvalSet(), crossDomain = nullptr;
    if (!evalSet.is_null()) {
        std::vector<int> ys; std::vector<double> ss;
        for (auto& s : evalSet["urlSamples"]) {
            std::string u = s["url"].get<std::string>();
            auto f = features::urlFeatures(u);
            ys.push_back(s["label"] == "phishing");
            ss.push_back(0.6 * gb.predictProba(f.data()) + 0.4 * clr.predictProba(cv.transform(features::canonicalUrlForModel(u))));
        }
        auto m = evaluateBinary(ys, ss);
        logMetrics("ensemble/hand-written-set", m);
        crossDomain = m.toJson();
    }
    json imp = json::array();
    std::vector<std::pair<double, std::string>> fi;
    for (size_t f = 0; f < ds.d; ++f) fi.push_back({gb.gainImportance[f], ds.featureNames[f]});
    std::sort(fi.rbegin(), fi.rend());
    for (int k = 0; k < 12; ++k) imp.push_back({{"feature", fi[k].second}, {"importance", fi[k].first}});

    writeModel("url_model", {
        {"task", "Malicious / phishing URL detection (scheme-invariant: http vs https cannot change the verdict)"},
        {"algorithm", "Gradient Boosted Trees (250 trees, depth 7, 42 lexical/brand/homograph features) + character 3-5 gram TF-IDF Logistic Regression, ensemble 0.6/0.4"},
        {"dataset", {{"name", "faizann24 malicious-URL dataset + Phishing.Database ACTIVE sample"}, {"samples", urls.size()},
                     {"split", "group split by registrable domain (no domain in both train and test)"},
                     {"trainSamples", tr.size()}, {"testSamples", te.size()}}},
        {"metrics", {{"ensemble", mEns.toJson()}, {"gbdt", mGb.toJson()}, {"charNgramLogReg", mLr.toJson()},
                     {"handWrittenSet", crossDomain}, {"schemeInvarianceMismatches", schemeMismatch}}},
        {"featureImportance", imp}, {"featureNames", ds.featureNames}, {"threshold", 0.5}, {"ensembleWeights", {0.6, 0.4}},
        {"gbdt", gb.toJson()}, {"charVectorizer", cv.toJson()}, {"charLogisticRegression", clr.toJson()}});
}

// ================================================================= NIDS ==
static void loadKdd(const std::string& path, DenseDataset& ds, std::vector<int>& cat) {
    std::ifstream in(path);
    std::string line;
    const auto& classes = features::nidsClasses();
    while (std::getline(in, line)) {
        std::vector<std::string> f;
        std::stringstream ss(line);
        std::string tok;
        while (std::getline(ss, tok, ',')) f.push_back(tok);
        if (f.size() < 42) continue;
        features::ConnRecord c;
        c.duration = std::stod(f[0]); c.protocol = f[1]; c.service = f[2]; c.flag = f[3];
        c.srcBytes = std::stod(f[4]); c.dstBytes = std::stod(f[5]); c.land = std::stoi(f[6]);
        c.wrongFragment = std::stoi(f[7]); c.urgent = std::stoi(f[8]);
        double* t[] = {&c.count, &c.srvCount, &c.serrorRate, &c.srvSerrorRate, &c.rerrorRate, &c.srvRerrorRate,
                       &c.sameSrvRate, &c.diffSrvRate, &c.srvDiffHostRate, &c.dstHostCount, &c.dstHostSrvCount,
                       &c.dstHostSameSrvRate, &c.dstHostDiffSrvRate, &c.dstHostSameSrcPortRate, &c.dstHostSrvDiffHostRate,
                       &c.dstHostSerrorRate, &c.dstHostSrvSerrorRate, &c.dstHostRerrorRate, &c.dstHostSrvRerrorRate};
        for (int k = 0; k < 19; ++k) *t[k] = std::stod(f[22 + k]);
        std::string category = features::kddAttackCategory(f[41]);
        int ci = static_cast<int>(std::find(classes.begin(), classes.end(), category) - classes.begin());
        ds.addRow(features::nidsFeatureVector(c), ci != 0);
        cat.push_back(ci);
    }
}

static void trainNids() {
    std::cout << "\n== Network Intrusion Detection models (NSL-KDD, header-derivable features)\n";
    DenseDataset trainDs, testDs;
    std::vector<int> trainCat, testCat;
    trainDs.featureNames = testDs.featureNames = features::nidsFeatureNames();
    loadKdd(DATA + "/KDDTrain.txt", trainDs, trainCat);
    loadKdd(DATA + "/KDDTest.txt", testDs, testCat);
    std::cout << "  KDDTrain+: " << trainDs.n << "  KDDTest+: " << testDs.n << "  features: " << trainDs.d << "\n";
    std::vector<size_t> all(trainDs.n);
    std::iota(all.begin(), all.end(), 0);

    // 1) Binary attack detector (GBDT)
    GradientBoostedTrees gb;
    GradientBoostedTrees::Params gp;
    gp.nTrees = 200; gp.maxDepth = 6; gp.learningRate = 0.1;
    gb.fit(trainDs, all, gp);
    std::vector<double> sGb;
    for (size_t i = 0; i < testDs.n; ++i) sGb.push_back(gb.predictProba(testDs.row(i)));
    auto mGb = evaluateBinary(testDs.y, sGb);
    logMetrics("gbdt attack-vs-normal (KDDTest+)", mGb);

    // 2) Attack category classifier (Random Forest, 5 classes)
    DenseDataset catDs = trainDs;
    catDs.y = trainCat;
    RandomForest rf;
    RandomForest::Params rp;
    rp.nTrees = 60; rp.maxDepth = 18; rp.minSamplesLeaf = 3; rp.threads = 2;
    rf.fit(catDs, all, 5, rp);
    std::vector<int> pred;
    std::vector<double> sRf;
    for (size_t i = 0; i < testDs.n; ++i) {
        auto p = rf.predictProba(testDs.row(i));
        pred.push_back(static_cast<int>(std::max_element(p.begin(), p.end()) - p.begin()));
        sRf.push_back(1.0 - p[0]);
    }
    auto mRf = evaluateMulticlass(testCat, pred, features::nidsClasses());
    auto mRfBin = evaluateBinary(testDs.y, sRf);
    std::cout << "  [random forest 5-class] acc=" << mRf.accuracy << " macroF1=" << mRf.macroF1 << "\n";
    for (size_t c = 0; c < 5; ++c) std::cout << "     " << mRf.classes[c] << ": recall=" << mRf.perClassRecall[c] << " f1=" << mRf.perClassF1[c] << "\n";
    logMetrics("random forest as attack detector", mRfBin);

    // 3) Zero-day anomaly detector: Isolation Forest trained on NORMAL traffic only
    std::vector<size_t> normalRows;
    for (size_t i = 0; i < trainDs.n; ++i) if (trainDs.y[i] == 0) normalRows.push_back(i);
    IsolationForest iso;
    IsolationForest::Params ip;
    ip.nTrees = 200; ip.sampleSize = 512; ip.contamination = 0.02;
    iso.fit(trainDs, normalRows, ip);
    std::vector<double> sIso;
    for (size_t i = 0; i < testDs.n; ++i) sIso.push_back(iso.score(testDs.row(i)));
    auto mIso = evaluateBinary(testDs.y, sIso, iso.threshold);
    logMetrics("isolation forest (normal-only training)", mIso);

    // Ensemble used at inference: max of GBDT and RF, with IF as a novelty flag.
    std::vector<double> sEns;
    for (size_t i = 0; i < testDs.n; ++i) sEns.push_back(std::max(sGb[i], sRf[i]) * 0.85 + (sIso[i] >= iso.threshold ? 0.15 : 0));
    auto mEns = evaluateBinary(testDs.y, sEns);
    logMetrics("ensemble (KDDTest+)", mEns);

    json imp = json::array();
    std::vector<std::pair<double, std::string>> fi;
    for (size_t f = 0; f < trainDs.d; ++f) fi.push_back({gb.gainImportance[f], trainDs.featureNames[f]});
    std::sort(fi.rbegin(), fi.rend());
    for (int k = 0; k < 12; ++k) imp.push_back({{"feature", fi[k].second}, {"importance", fi[k].first}});

    writeModel("nids_model", {
        {"task", "Network intrusion detection on connection records reconstructed from pcap / live capture"},
        {"algorithm", "Gradient Boosted Trees (attack vs normal) + Random Forest (normal/DoS/Probe/R2L/U2R) + Isolation Forest trained on normal traffic (zero-day novelty)"},
        {"dataset", {{"name", "NSL-KDD (KDDTrain+ / KDDTest+)"}, {"trainSamples", trainDs.n}, {"testSamples", testDs.n},
                     {"split", "official KDDTest+ (contains attack types absent from training)"},
                     {"note", "Only the 28 header-derivable features are used (13 payload/content features excluded) so live pcap traffic yields the same vector. R2L/U2R attacks are mostly visible only in payloads, so their recall is low by design."}}},
        {"metrics", {{"ensemble", mEns.toJson()}, {"gbdt", mGb.toJson()}, {"randomForest", mRf.toJson()},
                     {"randomForestBinary", mRfBin.toJson()}, {"isolationForest", mIso.toJson()}}},
        {"featureImportance", imp}, {"featureNames", trainDs.featureNames}, {"classes", features::nidsClasses()},
        {"gbdt", gb.toJson()}, {"randomForest", rf.toJson()}, {"isolationForest", iso.toJson()}});
}

// ======================================================= LOGIN ANOMALY ==
static features::LoginFeatureInput synthNormalLogin(std::mt19937& rng, double avgHour, double stdHour) {
    std::normal_distribution<double> hourN(avgHour, stdHour);
    std::uniform_real_distribution<double> U(0, 1);
    std::lognormal_distribution<double> localKm(std::log(8.0), 1.0), minutes(std::log(720.0), 1.2);
    features::LoginFeatureInput in;
    in.avgLoginHour = avgHour;
    in.loginHourStd = stdHour;
    in.hourOfDay = ((static_cast<int>(std::round(hourN(rng))) % 24) + 24) % 24;
    double r = U(rng);
    in.failedAttempts15Min = r < 0.86 ? 0 : (r < 0.96 ? 1 : (r < 0.99 ? 2 : 3));
    in.knownDevice = U(rng) < 0.95;
    in.minutesSinceLast = std::min(60.0 * 24 * 30, minutes(rng));
    double t = U(rng);
    if (t < 0.8) in.distanceKm = std::min(40.0, localKm(rng));
    else if (t < 0.95) in.distanceKm = 40 + U(rng) * 400;
    else {  // genuine travel: distance consistent with elapsed time (<= 800 km/h)
        in.distanceKm = 500 + U(rng) * 2500;
        in.minutesSinceLast = std::max(in.minutesSinceLast, in.distanceKm / 700.0 * 60 + 120);
    }
    return in;
}

static void trainLogin() {
    std::cout << "\n== Login anomaly model (Isolation Forest, unsupervised)\n";
    std::mt19937 rng(21);
    std::normal_distribution<double> avgN(13, 2.5);
    std::uniform_real_distribution<double> U(0, 1), stdU(1.5, 4.0);
    DenseDataset ds;
    ds.featureNames = features::loginFeatureNames();
    for (int user = 0; user < 800; ++user) {
        double avg = std::clamp(avgN(rng), 7.0, 21.0), sd = stdU(rng);
        for (int k = 0; k < 30; ++k) ds.addRow(features::loginFeatures(synthNormalLogin(rng, avg, sd)), 0);
    }
    std::vector<size_t> all(ds.n);
    std::iota(all.begin(), all.end(), 0);
    IsolationForest iso;
    IsolationForest::Params ip;
    ip.nTrees = 200; ip.sampleSize = 256; ip.contamination = 0.02; ip.useEnvelope = true;
    iso.fit(ds, all, ip);

    // Validation: fresh normal logins vs attack scenarios.
    std::vector<int> yv;
    std::vector<double> sv;
    for (int k = 0; k < 3000; ++k) {
        auto f = features::loginFeatures(synthNormalLogin(rng, std::clamp(avgN(rng), 7.0, 21.0), stdU(rng)));
        yv.push_back(0); sv.push_back(iso.score(f.data()));
    }
    for (int k = 0; k < 1000; ++k) {
        features::LoginFeatureInput a = synthNormalLogin(rng, std::clamp(avgN(rng), 7.0, 21.0), stdU(rng));
        int scenario = k % 4;
        if (scenario == 0) { a.failedAttempts15Min = 6 + rng() % 30; a.knownDevice = false; }                  // brute force / spraying
        if (scenario == 1) { a.distanceKm = 1500 + U(rng) * 6000; a.minutesSinceLast = 5 + U(rng) * 60; }     // impossible travel
        if (scenario == 2) { a.knownDevice = false; a.hourOfDay = (static_cast<int>(a.avgLoginHour) + 12) % 24; a.distanceKm = 800 + U(rng) * 3000; } // new device, odd hour, far
        if (scenario == 3) { a.failedAttempts15Min = 4 + rng() % 6; a.hourOfDay = (static_cast<int>(a.avgLoginHour) + 11) % 24; a.knownDevice = false; }
        auto f = features::loginFeatures(a);
        yv.push_back(1); sv.push_back(iso.score(f.data()));
    }
    auto m = evaluateBinary(yv, sv, iso.threshold);
    logMetrics("isolation forest (synthetic validation)", m);
    writeModel("login_anomaly", {
        {"task", "Credential theft / account takeover: anomalous login behaviour"},
        {"algorithm", "Isolation Forest (200 trees, 8 behavioural features) + learned robust-percentile envelope; retrainable on your own auth_events history via /ml/train/login"},
        {"dataset", {{"name", "Synthetic baseline of normal login behaviour (800 users x 30 logins)"},
                     {"note", "Unsupervised: learns what normal looks like. Validated on held-out normal logins vs simulated brute-force, impossible-travel and new-device attacks. Retrain on real history once enough logins exist."},
                     {"trainSamples", ds.n}}},
        {"metrics", {{"syntheticValidation", m.toJson()}}},
        {"featureNames", ds.featureNames}, {"isolationForest", iso.toJson()}});
}

// ========================================================= LOG ANOMALY ==
static json synthNormalEntityLogs(std::mt19937& rng, const std::string& id, bool isApiClient) {
    std::uniform_real_distribution<double> U(0, 1);
    json e = json::array();
    int n = 5 + rng() % 300;
    // Each entity has its own activity mix (some only call APIs, some only
    // read files, most do a bit of everything).
    std::vector<double> mix(5);
    for (auto& m : mix) m = std::pow(U(rng), 2.0);
    if (U(rng) < 0.3) { std::fill(mix.begin(), mix.end(), 0.0); mix[rng() % 5] = 1.0; }
    double tot = std::accumulate(mix.begin(), mix.end(), 0.0) + 1e-9;
    for (auto& m : mix) m /= tot;
    std::vector<std::string> endpoints = {"/api/items", "/api/profile", "/api/search", "/api/cart", "/api/orders", "/api/login", "/api/feed"};
    endpoints.resize(1 + rng() % endpoints.size());
    int nPorts = 1 + rng() % 4;
    for (int k = 0; k < n; ++k) {
        json ev;
        if (isApiClient) ev["sourceIp"] = id; else ev["userId"] = id;
        double r = U(rng), c = 0;
        int kind = 4;
        for (int t = 0; t < 5; ++t) { c += mix[t]; if (r < c) { kind = t; break; } }
        r = kind == 0 ? 0.2 : kind == 1 ? 0.5 : kind == 2 ? 0.8 : kind == 3 ? 0.9 : 0.97;
        if (r < 0.45) { ev["apiEndpoint"] = endpoints[rng() % endpoints.size()]; ev["httpStatus"] = U(rng) < 0.05 ? 404 : 200; }
        else if (r < 0.7) { ev["destinationPort"] = std::vector<int>{443, 80, 53, 22, 8080}[rng() % nPorts]; ev["eventType"] = "connection"; }
        else if (r < 0.85) { ev["filePath"] = "/home/" + id + "/docs/file" + std::to_string(rng() % 25) + ".pdf"; ev["eventType"] = "file_read"; }
        else if (r < 0.95) { ev["processName"] = std::vector<std::string>{"chrome.exe", "code.exe", "outlook.exe", "teams.exe"}[rng() % 4]; }
        else { ev["bytesTransferred"] = std::exp(std::log(2e6) + 1.5 * std::normal_distribution<double>(0, 1)(rng)); ev["hourOfDay"] = 9 + rng() % 10; }
        if (U(rng) < 0.003) ev["eventType"] = "admin_access";
        // rare but legitimate: scheduled off-hours backup, IT admin script
        if (U(rng) < 0.002) { ev["bytesTransferred"] = 1.5e8 + U(rng) * 3e8; ev["hourOfDay"] = 1 + rng() % 3; }
        if (U(rng) < 0.001) { ev["processName"] = "powershell.exe"; ev["commandLine"] = "powershell -EncodedCommand <it-maintenance>"; }
        e.push_back(ev);
    }
    return e;
}

static void trainLogs() {
    std::cout << "\n== Log behaviour anomaly model (Isolation Forest per user / source IP)\n";
    std::mt19937 rng(33);
    DenseDataset ds;
    ds.featureNames = features::logEntityFeatureNames();
    for (int k = 0; k < 4000; ++k)
        for (auto& [id, f] : features::logEntityFeatures(synthNormalEntityLogs(rng, "e" + std::to_string(k), k % 2)))
            ds.addRow(f, 0);
    std::vector<size_t> all(ds.n);
    std::iota(all.begin(), all.end(), 0);
    IsolationForest iso;
    IsolationForest::Params ip;
    ip.nTrees = 200; ip.sampleSize = 256; ip.contamination = 0.02; ip.useEnvelope = true;
    iso.fit(ds, all, ip);

    std::vector<int> yv;
    std::vector<double> sv;
    for (int k = 0; k < 1500; ++k)
        for (auto& [id, f] : features::logEntityFeatures(synthNormalEntityLogs(rng, "v" + std::to_string(k), k % 2))) { yv.push_back(0); sv.push_back(iso.score(f.data())); }
    for (int k = 0; k < 500; ++k) {
        json e = synthNormalEntityLogs(rng, "a" + std::to_string(k), true);
        int s = k % 5;
        for (int j = 0; j < 60; ++j) {
            json ev = {{"sourceIp", "a" + std::to_string(k)}};
            if (s == 0) ev["destinationPort"] = 1 + rng() % 5000;                                       // port scan
            if (s == 1) { ev["apiEndpoint"] = "/api/login"; ev["httpStatus"] = 401; }                  // credential stuffing
            if (s == 2 && j < 3) { ev["bytesTransferred"] = 3e9; ev["hourOfDay"] = 2; }               // exfiltration
            if (s == 3) { ev["eventType"] = j % 3 ? "mass_download" : "role_escalation"; ev["filePath"] = "/data/f" + std::to_string(j); }
            if (s == 4) { ev["processName"] = "svc.exe"; if (j < 3) ev["commandLine"] = "powershell -EncodedCommand AAAA"; }
            e.push_back(ev);
        }
        for (auto& [id, f] : features::logEntityFeatures(e)) { yv.push_back(1); sv.push_back(iso.score(f.data())); }
    }
    auto m = evaluateBinary(yv, sv, iso.threshold);
    logMetrics("isolation forest (synthetic validation)", m);
    writeModel("log_anomaly", {
        {"task", "Technical threats in auth/network/API/system logs: abnormal per-user and per-IP behaviour"},
        {"algorithm", "Isolation Forest (200 trees, 12 aggregated behaviour features per entity) + learned robust-percentile envelope, alongside the rule detectors"},
        {"dataset", {{"name", "Synthetic baseline of normal user/API-client activity (4000 entities)"},
                     {"note", "Unsupervised novelty detection; validated against simulated port scans, credential stuffing, exfiltration, insider bulk access and encoded-PowerShell malware."},
                     {"trainSamples", ds.n}}},
        {"metrics", {{"syntheticValidation", m.toJson()}}},
        {"featureNames", ds.featureNames}, {"isolationForest", iso.toJson()}});
}

// ================================================================ IMAGE ==
using features::RgbImage;

static RgbImage jpegRoundTrip(const RgbImage& im, int q) {
    RgbImage o;
    features::decodeImage(features::encodeJpeg(im, q), o);
    return o.w ? o : im;
}

static void boxBlurRegion(RgbImage& im, int x0, int y0, int w, int h, int r) {
    RgbImage src = im;
    for (int y = y0; y < y0 + h && y < im.h; ++y)
        for (int x = x0; x < x0 + w && x < im.w; ++x)
            for (int c = 0; c < 3; ++c) {
                int s = 0, n = 0;
                for (int dy = -r; dy <= r; ++dy)
                    for (int dx = -r; dx <= r; ++dx) {
                        int yy = std::clamp(y + dy, 0, im.h - 1), xx = std::clamp(x + dx, 0, im.w - 1);
                        s += src.px[(static_cast<size_t>(yy) * im.w + xx) * 3 + c]; n++;
                    }
                im.px[(static_cast<size_t>(y) * im.w + x) * 3 + c] = static_cast<uint8_t>(s / n);
            }
}

struct Rect { int x = 0, y = 0, w = 0, h = 0; bool local = false; };

static RgbImage manipulate(const RgbImage& base, const std::vector<RgbImage>& donors, std::mt19937& rng, std::string& kind, Rect& rect) {
    std::uniform_int_distribution<int> q(50, 80);
    RgbImage im = base;
    int type = rng() % 6;
    int pw = 64 + rng() % 80, ph = 64 + rng() % 80;
    int px = rng() % std::max(1, im.w - pw), py = rng() % std::max(1, im.h - ph);
    rect = {px, py, pw, ph, true};
    switch (type) {
        case 0: {  // splice from another image with a different compression history
            kind = "splice";
            const RgbImage& d = donors[rng() % donors.size()];
            RgbImage patch = jpegRoundTrip(features::cropAt(d, rng() % std::max(1, d.w - pw), rng() % std::max(1, d.h - ph), pw, ph), q(rng));
            for (int y = 0; y < patch.h; ++y)
                for (int x = 0; x < patch.w; ++x)
                    for (int c = 0; c < 3; ++c) im.px[(static_cast<size_t>(py + y) * im.w + px + x) * 3 + c] = patch.px[(static_cast<size_t>(y) * patch.w + x) * 3 + c];
            break;
        }
        case 1: {  // copy-move inside the same image
            kind = "copy_move";
            RgbImage patch = jpegRoundTrip(features::cropAt(im, rng() % std::max(1, im.w - pw), rng() % std::max(1, im.h - ph), pw, ph), q(rng));
            for (int y = 0; y < patch.h; ++y)
                for (int x = 0; x < patch.w; ++x)
                    for (int c = 0; c < 3; ++c) im.px[(static_cast<size_t>(py + y) * im.w + px + x) * 3 + c] = patch.px[(static_cast<size_t>(y) * patch.w + x) * 3 + c];
            break;
        }
        case 2: kind = "local_retouch_blur"; boxBlurRegion(im, px, py, pw, ph, 2 + rng() % 2); break;
        case 3: {  // generative-style smoothing / upscaling of the whole crop
            kind = "resample_upscale";
            rect.local = false;
            double sc = 0.35 + (rng() % 30) / 100.0;
            im = features::resizeBilinear(features::resizeBilinear(im, std::max(16, static_cast<int>(im.w * sc)), std::max(16, static_cast<int>(im.h * sc))), base.w, base.h);
            break;
        }
        case 4: {  // local noise injection (noise-level inconsistency)
            kind = "noise_inconsistency";
            std::normal_distribution<double> N(0, 6 + rng() % 8);
            for (int y = py; y < py + ph; ++y)
                for (int x = px; x < px + pw; ++x)
                    for (int c = 0; c < 3; ++c) {
                        auto& v = im.px[(static_cast<size_t>(y) * im.w + x) * 3 + c];
                        v = static_cast<uint8_t>(std::clamp(v + N(rng), 0.0, 255.0));
                    }
            break;
        }
        default: {  // double JPEG compression with misaligned grid
            kind = "double_compression";
            rect.local = false;
            RgbImage shifted = features::cropAt(jpegRoundTrip(base, q(rng)), 3, 5, base.w - 3, base.h - 5);
            im = features::resizeBilinear(shifted, base.w, base.h);
            break;
        }
    }
    return im;
}

static double overlap(const Rect& r, int bx, int by, int bs) {
    int x0 = std::max(r.x, bx), y0 = std::max(r.y, by), x1 = std::min(r.x + r.w, bx + bs), y1 = std::min(r.y + r.h, by + bs);
    return (x1 > x0 && y1 > y0) ? static_cast<double>((x1 - x0) * (y1 - y0)) / (bs * bs) : 0.0;
}

static void trainImage() {
    std::cout << "\n== Image manipulation model (block-level GBDT for local edits + global GBDT for whole-image edits)\n";
    std::vector<std::pair<std::string, RgbImage>> originals;
    for (auto& e : fs::directory_iterator(DATA + "/images/originals")) {
        RgbImage im;
        if (features::decodeImage(readFile(e.path().string()), im) && im.w >= 256 && im.h >= 256)
            originals.push_back({e.path().filename().string(), im});
    }
    std::sort(originals.begin(), originals.end(), [](auto& a, auto& b) { return a.first < b.first; });
    std::cout << "  source images: " << originals.size() << "\n";
    std::vector<RgbImage> donors;
    for (auto& o : originals) donors.push_back(o.second);

    struct Sample { RgbImage img; int label; bool local; Rect rect; int group; std::string kind; };
    std::vector<Sample> samples;
    std::mt19937 rng(77);
    std::uniform_int_distribution<int> qBenign(72, 97);
    std::map<std::string, int> kinds;
    for (size_t g = 0; g < originals.size(); ++g) {
        const RgbImage& src = originals[g].second;
        for (int k = 0; k < 40; ++k) {
            int side = std::min({256, src.w, src.h});
            RgbImage crop = features::cropAt(src, rng() % std::max(1, src.w - side + 1), rng() % std::max(1, src.h - side + 1), side, side);
            // Both classes get realistic benign processing (one JPEG save) so the
            // model cannot simply learn "was JPEG-compressed".
            if (rng() % 2) crop = jpegRoundTrip(crop, qBenign(rng));
            std::string kind;
            Rect rect;
            RgbImage fake = manipulate(crop, donors, rng, kind, rect);
            if (rng() % 2) fake = jpegRoundTrip(fake, qBenign(rng));
            kinds[kind]++;
            samples.push_back({crop, 0, false, {}, static_cast<int>(g), "original"});
            samples.push_back({fake, 1, rect.local, rect, static_cast<int>(g), kind});
        }
    }
    auto isTest = [](int g) { return g % 5 == 2; };  // whole source images held out

    // Global model: originals vs whole-image manipulations.
    DenseDataset gds;
    gds.featureNames = features::imageFeatureNames();
    std::vector<size_t> gtr;
    // Block model: blocks inside edited regions vs blocks of untouched content.
    DenseDataset bds;
    bds.featureNames = features::imageBlockFeatureNames();
    std::vector<size_t> btr;
    std::vector<std::vector<features::BlockFeatures>> blocksPer(samples.size());
    std::vector<std::vector<float>> globalPer(samples.size());
    for (size_t i = 0; i < samples.size(); ++i) {
        auto& s = samples[i];
        blocksPer[i] = features::imageBlockFeatures(s.img);
        globalPer[i] = features::imageFeatures(s.img);
        if (isTest(s.group)) continue;
        if (s.label == 0 || !s.local) { gds.addRow(globalPer[i], s.label); gtr.push_back(gds.n - 1); }
        for (auto& b : blocksPer[i]) {
            double ov = s.local ? overlap(s.rect, b.x, b.y, b.size) : 0.0;
            if (s.label == 1 && !s.local) continue;
            if (ov >= 0.5) { bds.addRow(b.f, 1); btr.push_back(bds.n - 1); }
            else if (ov == 0.0 && rng() % 4 == 0) { bds.addRow(b.f, 0); btr.push_back(bds.n - 1); }
        }
    }
    std::cout << "  global training rows " << gds.n << ", block training rows " << bds.n << "\n";
    GradientBoostedTrees globalModel, blockModel;
    GradientBoostedTrees::Params gp;
    gp.nTrees = 250; gp.maxDepth = 4; gp.learningRate = 0.08; gp.minSamplesLeaf = 8;
    globalModel.fit(gds, gtr, gp);
    GradientBoostedTrees::Params bp;
    bp.nTrees = 300; bp.maxDepth = 5; bp.learningRate = 0.08; bp.minSamplesLeaf = 20;
    blockModel.fit(bds, btr, bp);

    // Stage 2 (stacking): out-of-fold block + global predictions on TRAINING
    // images via 2-fold cross-fitting over source groups.
    auto buildBlockDs = [&](auto groupFilter, DenseDataset& out, std::vector<size_t>& rows) {
        out.featureNames = features::imageBlockFeatureNames();
        std::mt19937 r2(91);
        for (size_t i = 0; i < samples.size(); ++i) {
            auto& sm = samples[i];
            if (isTest(sm.group) || !groupFilter(sm.group) || (sm.label == 1 && !sm.local)) continue;
            for (auto& b : blocksPer[i]) {
                double ov = sm.local ? overlap(sm.rect, b.x, b.y, b.size) : 0.0;
                if (ov >= 0.5) { out.addRow(b.f, 1); rows.push_back(out.n - 1); }
                else if (ov == 0.0 && r2() % 4 == 0) { out.addRow(b.f, 0); rows.push_back(out.n - 1); }
            }
        }
    };
    auto buildGlobalDs = [&](auto groupFilter, DenseDataset& out, std::vector<size_t>& rows) {
        out.featureNames = features::imageFeatureNames();
        for (size_t i = 0; i < samples.size(); ++i) {
            auto& sm = samples[i];
            if (isTest(sm.group) || !groupFilter(sm.group) || (sm.label == 1 && sm.local)) continue;
            out.addRow(globalPer[i], sm.label); rows.push_back(out.n - 1);
        }
    };
    DenseDataset stackDs;
    stackDs.featureNames = {"global_prob", "block_top1", "block_top2_mean", "block_top4_mean", "block_mean",
                            "frac_blocks_over_0.5", "frac_blocks_over_0.9", "best_2x2_neighbourhood"};
    std::vector<size_t> stackRows;
    for (int fold = 0; fold < 2; ++fold) {
        auto inFold = [fold](int g) { return (g / 5 + g) % 2 == fold; };
        DenseDataset fb, fg; std::vector<size_t> rb, rg;
        buildBlockDs([&](int g) { return !inFold(g); }, fb, rb);
        buildGlobalDs([&](int g) { return !inFold(g); }, fg, rg);
        GradientBoostedTrees mb, mg;
        mb.fit(fb, rb, bp);
        mg.fit(fg, rg, gp);
        for (size_t i = 0; i < samples.size(); ++i) {
            if (isTest(samples[i].group) || !inFold(samples[i].group)) continue;
            stackDs.addRow(aggregateImageBlocks(mb, blocksPer[i], static_cast<float>(mg.predictProba(globalPer[i].data()))), samples[i].label);
            stackRows.push_back(stackDs.n - 1);
        }
    }
    GradientBoostedTrees stackModel;
    GradientBoostedTrees::Params sp;
    sp.nTrees = 150; sp.maxDepth = 3; sp.learningRate = 0.08; sp.minSamplesLeaf = 10; sp.colSample = 1.0;
    stackModel.fit(stackDs, stackRows, sp);

    // Image-level evaluation on unseen source images.
    std::vector<int> yte;
    std::vector<double> sAll, sLocalOnly, sGlobalOnly;
    std::map<std::string, std::pair<int, int>> perKind;
    for (size_t i = 0; i < samples.size(); ++i) {
        if (!isTest(samples[i].group)) continue;
        float gS = static_cast<float>(globalModel.predictProba(globalPer[i].data()));
        auto agg = aggregateImageBlocks(blockModel, blocksPer[i], gS);
        double sc = stackModel.predictProba(agg.data());
        yte.push_back(samples[i].label); sAll.push_back(sc); sLocalOnly.push_back(agg[2]); sGlobalOnly.push_back(gS);
        auto& pk = perKind[samples[i].kind];
        pk.second++;
        if (sc >= 0.5) pk.first++;
    }
    {   // block-level diagnostic on unseen images, per manipulation kind
        std::map<std::string, std::pair<std::vector<int>, std::vector<double>>> byKind;
        for (size_t i = 0; i < samples.size(); ++i) {
            auto& sm = samples[i];
            if (!isTest(sm.group) || (sm.label == 1 && !sm.local)) continue;
            for (auto& b : blocksPer[i]) {
                double ov = sm.local ? overlap(sm.rect, b.x, b.y, b.size) : 0.0;
                if (ov > 0 && ov < 0.5) continue;
                std::string k = sm.label == 0 ? "original" : sm.kind;
                double p = blockModel.predictProba(b.f.data());
                if (ov >= 0.5) { byKind[k].first.push_back(1); byKind[k].second.push_back(p); }
                byKind["_all"].first.push_back(ov >= 0.5); byKind["_all"].second.push_back(p);
            }
        }
        logMetrics("block-level (unseen images)", evaluateBinary(byKind["_all"].first, byKind["_all"].second));
    }
    auto m = evaluateBinary(yte, sAll), mL = evaluateBinary(yte, sLocalOnly), mG = evaluateBinary(yte, sGlobalOnly);
    logMetrics("stacked (unseen images)", m);
    logMetrics("block top-2 only", mL);
    logMetrics("global model only", mG);
    json kindJson;
    for (auto& [k, v] : perKind) {
        std::cout << "     " << k << ": flagged " << v.first << "/" << v.second << "\n";
        kindJson[k] = {{"flagged", v.first}, {"total", v.second}};
    }
    json imp = json::array();
    std::vector<std::pair<double, std::string>> fi;
    for (size_t f = 0; f < bds.d; ++f) fi.push_back({blockModel.gainImportance[f], bds.featureNames[f]});
    std::sort(fi.rbegin(), fi.rend());
    for (int k = 0; k < 8; ++k) imp.push_back({{"feature", fi[k].second}, {"importance", fi[k].first}});
    writeModel("image_manipulation", {
        {"task", "Image manipulation / tampering detection with localisation (splicing, copy-move, retouching, noise inconsistency, resampling, double compression)"},
        {"algorithm", "Block-level Gradient Boosted Trees on 14 relative forensic features per 32x32 block (ELA, noise residual, gradients, JPEG grid, vs the image's own medians and neighbours) + global Gradient Boosted Trees on 20 image-level features; a stacked GBDT combines global probability with block-score aggregates (top-k, hot-block fraction, best 2x2 neighbourhood) learned from out-of-fold predictions"},
        {"dataset", {{"name", "Public-domain photos (imageio + scikit-image sample images) with programmatic manipulations"},
                     {"sourceImages", originals.size()}, {"images", samples.size()}, {"manipulationTypes", kinds},
                     {"split", "held-out source images (never seen in training)"},
                     {"note", "EXPERIMENTAL (weak signal): trained on only 21 public-domain source photos, so generalisation is limited (see metrics). Detects editing/tampering traces and localises suspicious 32x32 blocks. It is NOT trained on GAN/diffusion face deepfakes (no such dataset was reachable); fully AI-generated faces are assessed by the Gemini vision layer. To improve it, add more original photos to datasets/images/originals and rerun: cg_train <datasets> <models> image (the trainer synthesises the manipulations). A labelled real-vs-fake folder mode is not implemented yet."}}},
        {"metrics", {{"stacked", m.toJson()}, {"blockTop2Only", mL.toJson()}, {"globalModelOnly", mG.toJson()}, {"perManipulationType", kindJson}}},
        {"featureImportance", imp}, {"featureNames", gds.featureNames}, {"blockFeatureNames", bds.featureNames}, {"threshold", 0.5},
        {"stackFeatureNames", stackDs.featureNames},
        {"gbdt", globalModel.toJson()}, {"blockGbdt", blockModel.toJson()}, {"stackGbdt", stackModel.toJson()}});
}

// ================================================================ AUDIO ==
static std::vector<float> loadWav16k(const std::string& path) {
    std::vector<float> x;
    int sr = 16000;
    if (!features::decodeWav(readFile(path), x, sr)) return {};
    return features::resampleLinear(x, sr, 16000);
}

static std::vector<float> griffinLim(const std::vector<float>& x, int iters, std::mt19937& rng) {
    const int nfft = 512, hop = 128;
    auto S = features::stft(x, nfft, hop);
    std::uniform_real_distribution<double> U(0, 2 * 3.14159265);
    std::vector<std::vector<std::complex<double>>> est = S;
    for (auto& fr : est) for (auto& v : fr) v = std::polar(std::abs(v), U(rng));
    std::vector<float> y;
    for (int it = 0; it < iters; ++it) {
        y = features::istft(est, nfft, hop, x.size());
        auto E = features::stft(y, nfft, hop);
        for (size_t f = 0; f < est.size() && f < E.size(); ++f)
            for (int k = 0; k < nfft; ++k) est[f][k] = std::polar(std::abs(S[f][k]), std::arg(E[f][k]));
    }
    return features::istft(est, nfft, hop, x.size());
}

static void trainAudio() {
    std::cout << "\n== Synthetic / cloned voice model (GBDT on 41 spectral + MFCC features)\n";
    std::mt19937 rng(55);
    std::normal_distribution<double> N(0, 1);
    DenseDataset ds;
    ds.featureNames = features::audioFeatureNames();
    std::vector<int> isTest;
    const size_t seg = 32000, hopSeg = 8000;  // 2 s windows, 0.5 s hop
    std::vector<std::string> realFiles, ttsFiles;
    for (auto& e : fs::directory_iterator(DATA + "/audio/real")) realFiles.push_back(e.path().string());
    for (auto& e : fs::directory_iterator(DATA + "/audio/tts")) ttsFiles.push_back(e.path().string());
    std::sort(realFiles.begin(), realFiles.end());
    std::sort(ttsFiles.begin(), ttsFiles.end());
    int nReal = 0, nGl = 0, nTts = 0;
    for (size_t fi = 0; fi < realFiles.size(); ++fi) {
        auto x = loadWav16k(realFiles[fi]);
        bool test = (fi == realFiles.size() - 1);  // hold out one speaker entirely
        for (size_t s = 0; s + seg <= x.size(); s += hopSeg) {
            std::vector<float> w(x.begin() + s, x.begin() + s + seg);
            for (int aug = 0; aug < 3; ++aug) {
                std::vector<float> a = w;
                double gain = 0.5 + (rng() % 100) / 100.0;
                for (auto& v : a) v = static_cast<float>(v * gain + (aug == 1 ? 0.003 * N(rng) : 0));
                if (aug == 2) a = features::resampleLinear(a, 16000, 16000 + static_cast<int>(rng() % 1600) - 800);
                ds.addRow(features::audioFeatures(a), 0); isTest.push_back(test); nReal++;
            }
            auto gl = griffinLim(w, 16 + rng() % 24, rng);  // vocoder-style resynthesis of the same speech
            ds.addRow(features::audioFeatures(gl), 1); isTest.push_back(test); nGl++;
        }
    }
    for (size_t fi = 0; fi < ttsFiles.size(); ++fi) {
        auto x = loadWav16k(ttsFiles[fi]);
        bool test = fi % 4 == 3;
        if (x.size() < seg) x.resize(seg, 0.0f);
        for (size_t s = 0; s + seg <= x.size(); s += seg / 2) {
            std::vector<float> w(x.begin() + s, x.begin() + s + seg);
            double gain = 0.5 + (rng() % 100) / 100.0;
            for (auto& v : w) v = static_cast<float>(v * gain);
            ds.addRow(features::audioFeatures(w), 1); isTest.push_back(test); nTts++;
        }
    }
    std::vector<size_t> tr, te;
    for (size_t i = 0; i < ds.n; ++i) (isTest[i] ? te : tr).push_back(i);
    std::cout << "  segments: real " << nReal << ", vocoder-resynthesised " << nGl << ", TTS " << nTts << " | train " << tr.size() << " test " << te.size() << "\n";
    GradientBoostedTrees gb;
    GradientBoostedTrees::Params gp;
    gp.nTrees = 200; gp.maxDepth = 3; gp.learningRate = 0.08; gp.minSamplesLeaf = 5;
    gb.fit(ds, tr, gp);
    std::vector<int> yte;
    std::vector<double> s;
    for (auto i : te) { yte.push_back(ds.y[i]); s.push_back(gb.predictProba(ds.row(i))); }
    auto m = evaluateBinary(yte, s);
    logMetrics("gbdt (unseen speaker + unseen TTS clips)", m);
    json imp = json::array();
    std::vector<std::pair<double, std::string>> fi;
    for (size_t f = 0; f < ds.d; ++f) fi.push_back({gb.gainImportance[f], ds.featureNames[f]});
    std::sort(fi.rbegin(), fi.rend());
    for (int k = 0; k < 10; ++k) imp.push_back({{"feature", fi[k].second}, {"importance", fi[k].first}});
    writeModel("audio_deepfake", {
        {"task", "Synthetic / cloned voice detection"},
        {"algorithm", "Gradient Boosted Trees (200 trees, depth 3) on 41 features: 13 MFCC means/stds, delta-MFCC, spectral centroid/rolloff/flatness/flux, ZCR, energy dynamics, band-energy ratios"},
        {"dataset", {{"name", "LibriSpeech clips (real, 3 speakers, augmented) vs Griffin-Lim vocoder resynthesis + espeak-ng TTS (72 clips, 6 voices)"},
                     {"samples", ds.n}, {"split", "held-out speaker and held-out TTS clips"},
                     {"note", "Proof-of-concept scale: real speech comes from only 3 speakers. Treat scores as one signal alongside Gemini's audio reasoning. Retrain on ASVspoof / WaveFake with: cg_train <dir> <models> audio (put WAVs in audio/real and audio/tts)."}}},
        {"metrics", {{"gbdt", m.toJson()}}}, {"featureImportance", imp}, {"featureNames", ds.featureNames}, {"threshold", 0.5},
        {"gbdt", gb.toJson()}});
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: cg_train <datasets_dir> <models_dir> [all|text|url|nids|login|logs|image|audio]\n";
        return 1;
    }
    DATA = argv[1];
    OUT = argv[2];
    std::string what = argc > 3 ? argv[3] : "all";
    fs::create_directories(OUT);
    for (auto p : {OUT + "/../data/public_suffix_list.dat", std::string("data/public_suffix_list.dat"), DATA + "/psl.dat"})
        if (PublicSuffixList::instance().load(p)) break;
    if (fs::exists(OUT + "/metrics_summary.json")) SUMMARY = json::parse(readFile(OUT + "/metrics_summary.json"));

    auto run = [&](const std::string& name, void (*fn)()) {
        if (what == "all" || what == name) {
            auto t0 = std::chrono::steady_clock::now();
            fn();
            std::cout << "  (" << name << " done in " << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t0).count() << "s)\n";
        }
    };
    run("text", trainText);
    run("url", trainUrl);
    run("nids", trainNids);
    run("login", trainLogin);
    run("logs", trainLogs);
    run("image", trainImage);
    run("audio", trainAudio);
    std::ofstream(OUT + "/metrics_summary.json") << SUMMARY.dump(2);
    std::cout << "\nSummary written to " << OUT << "/metrics_summary.json\n";
    return 0;
}
