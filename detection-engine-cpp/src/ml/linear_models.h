#pragma once
// Sparse logistic regression (AdaGrad SGD, L2, class-balanced) and
// multinomial Naive Bayes. Used for text (TF-IDF) and URL char n-grams.
#include <vector>
#include "ml_core.h"

namespace cyberguard::ml {

class LogisticRegression {
public:
    struct Params {
        int epochs = 6;
        double learningRate = 0.5;
        double l2 = 1e-6;
        bool balanced = true;
        unsigned seed = 42;
    };

    void fit(const std::vector<SparseVec>& X, const std::vector<int>& y, size_t dim, const Params& p);
    double predictProba(const SparseVec& x) const;
    // Per-feature contribution (weight * value), sorted by |contribution| desc.
    std::vector<std::pair<int, double>> topContributions(const SparseVec& x, size_t k) const;

    json toJson() const;
    static LogisticRegression fromJson(const json& j);

    std::vector<float> w;
    double b = 0;
    size_t dim = 0;
};

class MultinomialNB {
public:
    void fit(const std::vector<SparseVec>& X, const std::vector<int>& y, size_t dim, int nClasses = 2,
             double alpha = 1.0);
    std::vector<double> predictProba(const SparseVec& x) const;

    json toJson() const;
    static MultinomialNB fromJson(const json& j);

    std::vector<double> logPrior;
    std::vector<std::vector<float>> logLik;  // [class][feature]
    size_t dim = 0;
};

}  // namespace cyberguard::ml
