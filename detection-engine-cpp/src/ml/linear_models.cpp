#include "linear_models.h"

#include <algorithm>
#include <numeric>

namespace cyberguard::ml {

void LogisticRegression::fit(const std::vector<SparseVec>& X, const std::vector<int>& y, size_t dimension,
                             const Params& p) {
    dim = dimension;
    w.assign(dim, 0.0f);
    b = 0;
    std::vector<float> g2(dim, 0.0f);
    double g2b = 0;

    long nPos = std::count(y.begin(), y.end(), 1), nNeg = static_cast<long>(y.size()) - nPos;
    double cwPos = 1.0, cwNeg = 1.0;
    if (p.balanced && nPos > 0 && nNeg > 0) {
        cwPos = static_cast<double>(y.size()) / (2.0 * nPos);
        cwNeg = static_cast<double>(y.size()) / (2.0 * nNeg);
    }

    std::vector<size_t> order(X.size());
    std::iota(order.begin(), order.end(), 0);
    std::mt19937 rng(p.seed);
    const double eps = 1e-8;

    for (int epoch = 0; epoch < p.epochs; ++epoch) {
        std::shuffle(order.begin(), order.end(), rng);
        for (size_t idx : order) {
            const SparseVec& x = X[idx];
            double z = b;
            for (auto& [j, v] : x) z += w[j] * v;
            double pr = sigmoid(z);
            double g = (pr - y[idx]) * (y[idx] == 1 ? cwPos : cwNeg);
            for (auto& [j, v] : x) {
                double gj = g * v + p.l2 * w[j];
                g2[j] += static_cast<float>(gj * gj);
                w[j] -= static_cast<float>(p.learningRate * gj / (std::sqrt(g2[j]) + eps));
            }
            g2b += g * g;
            b -= p.learningRate * g / (std::sqrt(g2b) + eps);
        }
    }
}

double LogisticRegression::predictProba(const SparseVec& x) const {
    double z = b;
    for (auto& [j, v] : x)
        if (j >= 0 && static_cast<size_t>(j) < dim) z += w[j] * v;
    return sigmoid(z);
}

std::vector<std::pair<int, double>> LogisticRegression::topContributions(const SparseVec& x, size_t k) const {
    std::vector<std::pair<int, double>> c;
    for (auto& [j, v] : x)
        if (j >= 0 && static_cast<size_t>(j) < dim) c.emplace_back(j, w[j] * v);
    std::sort(c.begin(), c.end(), [](auto& a, auto& b) { return std::fabs(a.second) > std::fabs(b.second); });
    if (c.size() > k) c.resize(k);
    return c;
}

json LogisticRegression::toJson() const {
    // Store weights sparsely (most hashed/vocab weights are small but non-zero;
    // round to 5 significant digits to keep files compact).
    std::vector<float> rounded(w.size());
    for (size_t i = 0; i < w.size(); ++i) rounded[i] = std::round(w[i] * 1e5f) / 1e5f;
    return json{{"dim", dim}, {"bias", b}, {"weights", rounded}};
}

LogisticRegression LogisticRegression::fromJson(const json& j) {
    LogisticRegression m;
    m.dim = j.at("dim").get<size_t>();
    m.b = j.at("bias").get<double>();
    m.w = j.at("weights").get<std::vector<float>>();
    return m;
}

void MultinomialNB::fit(const std::vector<SparseVec>& X, const std::vector<int>& y, size_t dimension,
                        int nClasses, double alpha) {
    dim = dimension;
    std::vector<std::vector<double>> counts(nClasses, std::vector<double>(dim, 0.0));
    std::vector<double> classTotals(nClasses, 0.0), classDocs(nClasses, 0.0);
    for (size_t i = 0; i < X.size(); ++i) {
        classDocs[y[i]] += 1;
        for (auto& [j, v] : X[i]) {
            counts[y[i]][j] += v;
            classTotals[y[i]] += v;
        }
    }
    logPrior.assign(nClasses, 0);
    logLik.assign(nClasses, std::vector<float>(dim, 0));
    for (int c = 0; c < nClasses; ++c) {
        logPrior[c] = std::log((classDocs[c] + 1) / (X.size() + nClasses));
        double denom = classTotals[c] + alpha * dim;
        for (size_t j = 0; j < dim; ++j)
            logLik[c][j] = static_cast<float>(std::log((counts[c][j] + alpha) / denom));
    }
}

std::vector<double> MultinomialNB::predictProba(const SparseVec& x) const {
    std::vector<double> lp(logPrior);
    for (size_t c = 0; c < lp.size(); ++c)
        for (auto& [j, v] : x)
            if (j >= 0 && static_cast<size_t>(j) < dim) lp[c] += v * logLik[c][j];
    double mx = *std::max_element(lp.begin(), lp.end()), sum = 0;
    for (auto& v : lp) { v = std::exp(v - mx); sum += v; }
    for (auto& v : lp) v /= sum;
    return lp;
}

json MultinomialNB::toJson() const {
    json ll = json::array();
    for (auto& row : logLik) {
        std::vector<float> r(row.size());
        for (size_t i = 0; i < row.size(); ++i) r[i] = std::round(row[i] * 1e4f) / 1e4f;
        ll.push_back(r);
    }
    return json{{"dim", dim}, {"logPrior", logPrior}, {"logLik", ll}};
}

MultinomialNB MultinomialNB::fromJson(const json& j) {
    MultinomialNB m;
    m.dim = j.at("dim").get<size_t>();
    m.logPrior = j.at("logPrior").get<std::vector<double>>();
    for (auto& row : j.at("logLik")) m.logLik.push_back(row.get<std::vector<float>>());
    return m;
}

}  // namespace cyberguard::ml
