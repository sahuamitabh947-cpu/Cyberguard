#pragma once
// Tree ensembles implemented from scratch in C++:
//   * GradientBoostedTrees  - binary classifier, logistic loss, second-order
//                             (XGBoost-style) splits on histogram bins.
//   * RandomForest          - multi-class classifier (gini), bootstrap + mtry.
//   * IsolationForest       - unsupervised anomaly detector (Liu et al. 2008).
// All models expose per-prediction feature contributions so the dashboard can
// explain *why* a sample was flagged.
#include <cstdint>
#include <vector>
#include "ml_core.h"

namespace cyberguard::ml {

// Quantile binning shared by GBDT and RF training.
struct Binner {
    std::vector<std::vector<float>> edges;  // per feature, ascending; bin(v) = #edges < v
    void fit(const DenseDataset& ds, const std::vector<size_t>& rows, int maxBins, unsigned seed);
    uint8_t bin(size_t f, float v) const;
    size_t numBins(size_t f) const { return edges[f].size() + 1; }
};

struct TreeNode {
    int feature = -1;   // -1 => leaf
    float threshold = 0;  // go left if x[feature] <= threshold
    int left = -1, right = -1;
    float value = 0;    // GBDT: node output (scaled by learning rate)
    std::vector<float> dist;  // RF leaves: class distribution
};

class GradientBoostedTrees {
public:
    struct Params {
        int nTrees = 200;
        int maxDepth = 6;
        double learningRate = 0.1;
        double lambda = 1.0;
        double minChildWeight = 1.0;
        int minSamplesLeaf = 10;
        double rowSample = 0.8;
        double colSample = 0.8;
        int maxBins = 64;
        bool balanced = true;
        unsigned seed = 7;
    };

    void fit(const DenseDataset& ds, const std::vector<size_t>& rows, const Params& p);
    double predictMargin(const float* x) const;
    double predictProba(const float* x) const { return sigmoid(predictMargin(x)); }
    // Saabas-style path contributions per feature (sum ~= margin - base).
    std::vector<double> contributions(const float* x, size_t d) const;

    json toJson() const;
    static GradientBoostedTrees fromJson(const json& j);

    double baseScore = 0;
    std::vector<std::vector<TreeNode>> trees;
    std::vector<double> gainImportance;
};

class RandomForest {
public:
    struct Params {
        int nTrees = 60;
        int maxDepth = 16;
        int minSamplesLeaf = 3;
        int maxBins = 64;
        double featureFrac = -1;  // <0 => sqrt(d)/d
        double sampleFrac = 0.7;  // bootstrap sample size fraction
        bool balanced = true;
        unsigned seed = 11;
        int threads = 2;
    };

    void fit(const DenseDataset& ds, const std::vector<size_t>& rows, int nClasses, const Params& p);
    std::vector<double> predictProba(const float* x) const;
    int predict(const float* x) const;

    json toJson() const;
    static RandomForest fromJson(const json& j);

    int nClasses = 0;
    std::vector<std::vector<TreeNode>> trees;
    std::vector<double> gainImportance;
};

class IsolationForest {
public:
    struct Params {
        int nTrees = 150;
        int sampleSize = 256;
        unsigned seed = 3;
        double contamination = 0.01;  // expected anomaly share in training data
        // Robust percentile envelope: flags values far outside anything seen in
        // training (fixes Isolation Forest's blind spot on features that are
        // constant in normal data, e.g. "encoded commands = 0").
        bool useEnvelope = false;
        double envelopeQuantile = 0.001;
    };

    void fit(const DenseDataset& ds, const std::vector<size_t>& rows, const Params& p);
    // Anomaly score in (0,1]; > ~0.6 is anomalous in the classic formulation.
    // With the envelope enabled: max(isolation score, 0.5 + 0.5 * envelope).
    double score(const float* x) const;
    double isolationScore(const float* x) const;
    // 0 when at/below the learned upper envelope; -> 1 the further above it is.
    double envelopeScore(const float* x, int* worstFeature = nullptr) const;
    // Features most often used to isolate this point near the root.
    std::vector<double> isolationContributions(const float* x, size_t d) const;

    json toJson() const;
    static IsolationForest fromJson(const json& j);

    struct INode { int feature = -1; float threshold = 0; int left = -1, right = -1; int size = 0; };
    std::vector<std::vector<INode>> trees;
    int sampleSize = 256;
    double threshold = 0.6;  // score at the (1-contamination) training quantile
    bool useEnvelope = false;
    std::vector<float> envLo, envHi, envScale;
};

}  // namespace cyberguard::ml
