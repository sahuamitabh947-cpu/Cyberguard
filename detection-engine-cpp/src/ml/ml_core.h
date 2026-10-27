#pragma once
// CyberGuard ML core: datasets, splitting, metrics, scaling.
// Pure C++17, no external ML dependencies. Every model in the engine is
// trained and served with this code (see cg_train.cpp and model_registry.cpp).
#include <cmath>
#include <cstdint>
#include <random>
#include <string>
#include <utility>
#include <vector>
#include "json.hpp"

namespace cyberguard::ml {

using json = nlohmann::json;

// Sparse feature vector: (feature index, value), indices ascending.
using SparseVec = std::vector<std::pair<int, float>>;

inline double sigmoid(double z) {
    if (z >= 0) { double e = std::exp(-z); return 1.0 / (1.0 + e); }
    double e = std::exp(z); return e / (1.0 + e);
}

// Row-major dense dataset.
struct DenseDataset {
    std::vector<float> X;
    std::vector<int> y;
    size_t n = 0, d = 0;
    std::vector<std::string> featureNames;

    const float* row(size_t i) const { return X.data() + i * d; }
    void addRow(const std::vector<float>& r, int label);
};

// Stratified (when labels given) random split of row indices.
void trainTestSplit(size_t n, double testFrac, unsigned seed,
                    std::vector<size_t>& trainIdx, std::vector<size_t>& testIdx,
                    const std::vector<int>* stratifyY = nullptr);

struct BinaryMetrics {
    double accuracy = 0, precision = 0, recall = 0, f1 = 0, rocAuc = 0;
    long tp = 0, fp = 0, tn = 0, fn = 0;
    size_t n = 0;
    double threshold = 0.5;
    json toJson() const;
};
BinaryMetrics evaluateBinary(const std::vector<int>& yTrue, const std::vector<double>& scores,
                             double threshold = 0.5);

struct MulticlassMetrics {
    double accuracy = 0, macroF1 = 0;
    std::vector<std::string> classes;
    std::vector<double> perClassPrecision, perClassRecall, perClassF1;
    std::vector<std::vector<long>> confusion;  // [true][pred]
    size_t n = 0;
    json toJson() const;
};
MulticlassMetrics evaluateMulticlass(const std::vector<int>& yTrue, const std::vector<int>& yPred,
                                     const std::vector<std::string>& classes);

struct StandardScaler {
    std::vector<double> mean, stdv;
    void fit(const DenseDataset& ds, const std::vector<size_t>* rows = nullptr);
    void transformInPlace(float* row, size_t d) const;
    json toJson() const;
    static StandardScaler fromJson(const json& j);
};

// Utility: pick the threshold on validation scores that maximises F1.
double bestF1Threshold(const std::vector<int>& yTrue, const std::vector<double>& scores);

}  // namespace cyberguard::ml
