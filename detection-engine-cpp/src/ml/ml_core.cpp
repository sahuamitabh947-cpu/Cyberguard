#include "ml_core.h"

#include <algorithm>
#include <numeric>

namespace cyberguard::ml {

void DenseDataset::addRow(const std::vector<float>& r, int label) {
    if (d == 0) d = r.size();
    X.insert(X.end(), r.begin(), r.end());
    y.push_back(label);
    ++n;
}

void trainTestSplit(size_t n, double testFrac, unsigned seed, std::vector<size_t>& trainIdx,
                    std::vector<size_t>& testIdx, const std::vector<int>* stratifyY) {
    trainIdx.clear();
    testIdx.clear();
    std::mt19937 rng(seed);
    if (!stratifyY) {
        std::vector<size_t> idx(n);
        std::iota(idx.begin(), idx.end(), 0);
        std::shuffle(idx.begin(), idx.end(), rng);
        size_t nTest = static_cast<size_t>(n * testFrac);
        testIdx.assign(idx.begin(), idx.begin() + nTest);
        trainIdx.assign(idx.begin() + nTest, idx.end());
        return;
    }
    int maxLabel = 0;
    for (int v : *stratifyY) maxLabel = std::max(maxLabel, v);
    std::vector<std::vector<size_t>> byClass(maxLabel + 1);
    for (size_t i = 0; i < n; ++i) byClass[(*stratifyY)[i]].push_back(i);
    for (auto& cls : byClass) {
        std::shuffle(cls.begin(), cls.end(), rng);
        size_t nTest = static_cast<size_t>(cls.size() * testFrac);
        testIdx.insert(testIdx.end(), cls.begin(), cls.begin() + nTest);
        trainIdx.insert(trainIdx.end(), cls.begin() + nTest, cls.end());
    }
    std::shuffle(trainIdx.begin(), trainIdx.end(), rng);
}

json BinaryMetrics::toJson() const {
    return json{{"accuracy", accuracy}, {"precision", precision}, {"recall", recall},
                {"f1", f1},             {"rocAuc", rocAuc},       {"threshold", threshold},
                {"confusion", {{"tp", tp}, {"fp", fp}, {"tn", tn}, {"fn", fn}}},
                {"samples", n}};
}

static double rocAuc(const std::vector<int>& y, const std::vector<double>& s) {
    // Mann-Whitney U with tie handling.
    std::vector<size_t> idx(y.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return s[a] < s[b]; });
    double rankSumPos = 0;
    long nPos = 0, nNeg = 0;
    size_t i = 0;
    while (i < idx.size()) {
        size_t j = i;
        while (j + 1 < idx.size() && s[idx[j + 1]] == s[idx[i]]) ++j;
        double avgRank = (i + j) / 2.0 + 1.0;
        for (size_t k = i; k <= j; ++k)
            if (y[idx[k]] == 1) rankSumPos += avgRank;
        i = j + 1;
    }
    for (int v : y) (v == 1 ? nPos : nNeg)++;
    if (nPos == 0 || nNeg == 0) return 0.5;
    return (rankSumPos - nPos * (nPos + 1) / 2.0) / (static_cast<double>(nPos) * nNeg);
}

BinaryMetrics evaluateBinary(const std::vector<int>& yTrue, const std::vector<double>& scores,
                             double threshold) {
    BinaryMetrics m;
    m.n = yTrue.size();
    m.threshold = threshold;
    for (size_t i = 0; i < yTrue.size(); ++i) {
        bool pred = scores[i] >= threshold;
        if (yTrue[i] == 1 && pred) m.tp++;
        else if (yTrue[i] == 0 && pred) m.fp++;
        else if (yTrue[i] == 0 && !pred) m.tn++;
        else m.fn++;
    }
    m.accuracy = m.n ? static_cast<double>(m.tp + m.tn) / m.n : 0;
    m.precision = (m.tp + m.fp) ? static_cast<double>(m.tp) / (m.tp + m.fp) : 0;
    m.recall = (m.tp + m.fn) ? static_cast<double>(m.tp) / (m.tp + m.fn) : 0;
    m.f1 = (m.precision + m.recall) > 0 ? 2 * m.precision * m.recall / (m.precision + m.recall) : 0;
    m.rocAuc = rocAuc(yTrue, scores);
    return m;
}

json MulticlassMetrics::toJson() const {
    json perClass = json::array();
    for (size_t c = 0; c < classes.size(); ++c)
        perClass.push_back({{"class", classes[c]},
                            {"precision", perClassPrecision[c]},
                            {"recall", perClassRecall[c]},
                            {"f1", perClassF1[c]}});
    return json{{"accuracy", accuracy}, {"macroF1", macroF1}, {"perClass", perClass},
                {"confusion", confusion}, {"classes", classes}, {"samples", n}};
}

MulticlassMetrics evaluateMulticlass(const std::vector<int>& yTrue, const std::vector<int>& yPred,
                                     const std::vector<std::string>& classes) {
    MulticlassMetrics m;
    size_t k = classes.size();
    m.classes = classes;
    m.n = yTrue.size();
    m.confusion.assign(k, std::vector<long>(k, 0));
    long correct = 0;
    for (size_t i = 0; i < yTrue.size(); ++i) {
        m.confusion[yTrue[i]][yPred[i]]++;
        if (yTrue[i] == yPred[i]) correct++;
    }
    m.accuracy = m.n ? static_cast<double>(correct) / m.n : 0;
    m.perClassPrecision.assign(k, 0);
    m.perClassRecall.assign(k, 0);
    m.perClassF1.assign(k, 0);
    double sumF1 = 0;
    int present = 0;
    for (size_t c = 0; c < k; ++c) {
        long tp = m.confusion[c][c], colSum = 0, rowSum = 0;
        for (size_t r = 0; r < k; ++r) colSum += m.confusion[r][c];
        for (size_t p = 0; p < k; ++p) rowSum += m.confusion[c][p];
        double prec = colSum ? static_cast<double>(tp) / colSum : 0;
        double rec = rowSum ? static_cast<double>(tp) / rowSum : 0;
        m.perClassPrecision[c] = prec;
        m.perClassRecall[c] = rec;
        m.perClassF1[c] = (prec + rec) > 0 ? 2 * prec * rec / (prec + rec) : 0;
        if (rowSum > 0) { sumF1 += m.perClassF1[c]; present++; }
    }
    m.macroF1 = present ? sumF1 / present : 0;
    return m;
}

void StandardScaler::fit(const DenseDataset& ds, const std::vector<size_t>* rows) {
    mean.assign(ds.d, 0);
    stdv.assign(ds.d, 0);
    size_t cnt = rows ? rows->size() : ds.n;
    for (size_t k = 0; k < cnt; ++k) {
        const float* r = ds.row(rows ? (*rows)[k] : k);
        for (size_t j = 0; j < ds.d; ++j) mean[j] += r[j];
    }
    for (auto& m : mean) m /= std::max<size_t>(cnt, 1);
    for (size_t k = 0; k < cnt; ++k) {
        const float* r = ds.row(rows ? (*rows)[k] : k);
        for (size_t j = 0; j < ds.d; ++j) stdv[j] += (r[j] - mean[j]) * (r[j] - mean[j]);
    }
    for (auto& s : stdv) {
        s = std::sqrt(s / std::max<size_t>(cnt, 1));
        if (s < 1e-9) s = 1.0;
    }
}

void StandardScaler::transformInPlace(float* row, size_t d) const {
    for (size_t j = 0; j < d && j < mean.size(); ++j)
        row[j] = static_cast<float>((row[j] - mean[j]) / stdv[j]);
}

json StandardScaler::toJson() const { return json{{"mean", mean}, {"std", stdv}}; }

StandardScaler StandardScaler::fromJson(const json& j) {
    StandardScaler s;
    s.mean = j.at("mean").get<std::vector<double>>();
    s.stdv = j.at("std").get<std::vector<double>>();
    return s;
}

double bestF1Threshold(const std::vector<int>& yTrue, const std::vector<double>& scores) {
    double best = 0.5, bestF1 = -1;
    for (int t = 5; t <= 95; ++t) {
        double th = t / 100.0;
        auto m = evaluateBinary(yTrue, scores, th);
        if (m.f1 > bestF1) { bestF1 = m.f1; best = th; }
    }
    return best;
}

}  // namespace cyberguard::ml
