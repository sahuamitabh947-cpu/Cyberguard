#include "tree_models.h"

#include <algorithm>
#include <functional>
#include <numeric>
#include <thread>

namespace cyberguard::ml {

// ---------------------------------------------------------------- Binner --
void Binner::fit(const DenseDataset& ds, const std::vector<size_t>& rows, int maxBins, unsigned seed) {
    edges.assign(ds.d, {});
    std::vector<size_t> sample(rows);
    std::mt19937 rng(seed);
    if (sample.size() > 200000) {
        std::shuffle(sample.begin(), sample.end(), rng);
        sample.resize(200000);
    }
    std::vector<float> vals(sample.size());
    for (size_t f = 0; f < ds.d; ++f) {
        for (size_t i = 0; i < sample.size(); ++i) vals[i] = ds.row(sample[i])[f];
        std::sort(vals.begin(), vals.end());
        std::vector<float> uniq;
        for (float v : vals)
            if (uniq.empty() || v != uniq.back()) uniq.push_back(v);
        std::vector<float>& e = edges[f];
        if (uniq.size() <= static_cast<size_t>(maxBins)) {
            // exact: split after every distinct value except the last
            for (size_t i = 0; i + 1 < uniq.size(); ++i) e.push_back(uniq[i]);
        } else {
            for (int q = 1; q < maxBins; ++q) {
                float v = vals[static_cast<size_t>(static_cast<double>(q) / maxBins * (vals.size() - 1))];
                if (e.empty() || v > e.back()) e.push_back(v);
            }
            if (!e.empty() && e.back() >= uniq.back()) e.pop_back();
        }
    }
}

uint8_t Binner::bin(size_t f, float v) const {
    const auto& e = edges[f];
    return static_cast<uint8_t>(std::lower_bound(e.begin(), e.end(), v) - e.begin());
}

static std::vector<uint8_t> binMatrix(const DenseDataset& ds, const Binner& b) {
    std::vector<uint8_t> out(ds.n * ds.d);
    for (size_t i = 0; i < ds.n; ++i)
        for (size_t f = 0; f < ds.d; ++f) out[i * ds.d + f] = b.bin(f, ds.row(i)[f]);
    return out;
}

static json nodesToJson(const std::vector<TreeNode>& nodes, bool withValue, bool withDist) {
    std::vector<int> f, l, r;
    std::vector<float> t, v;
    json dists = json::array();
    for (auto& n : nodes) {
        f.push_back(n.feature);
        t.push_back(n.threshold);
        l.push_back(n.left);
        r.push_back(n.right);
        if (withValue) v.push_back(std::round(n.value * 1e6f) / 1e6f);
        if (withDist) {
            if (n.feature < 0) {
                std::vector<float> d(n.dist.size());
                for (size_t i = 0; i < d.size(); ++i) d[i] = std::round(n.dist[i] * 1e4f) / 1e4f;
                dists.push_back(d);
            } else dists.push_back(nullptr);
        }
    }
    json j{{"f", f}, {"t", t}, {"l", l}, {"r", r}};
    if (withValue) j["v"] = v;
    if (withDist) j["p"] = dists;
    return j;
}

static std::vector<TreeNode> nodesFromJson(const json& j) {
    auto f = j.at("f").get<std::vector<int>>();
    auto t = j.at("t").get<std::vector<float>>();
    auto l = j.at("l").get<std::vector<int>>();
    auto r = j.at("r").get<std::vector<int>>();
    std::vector<TreeNode> nodes(f.size());
    for (size_t i = 0; i < f.size(); ++i) {
        nodes[i].feature = f[i];
        nodes[i].threshold = t[i];
        nodes[i].left = l[i];
        nodes[i].right = r[i];
    }
    if (j.contains("v")) {
        auto v = j["v"].get<std::vector<float>>();
        for (size_t i = 0; i < v.size(); ++i) nodes[i].value = v[i];
    }
    if (j.contains("p")) {
        const auto& p = j["p"];
        for (size_t i = 0; i < p.size(); ++i)
            if (!p[i].is_null()) nodes[i].dist = p[i].get<std::vector<float>>();
    }
    return nodes;
}

// ------------------------------------------------------------------ GBDT --
void GradientBoostedTrees::fit(const DenseDataset& ds, const std::vector<size_t>& rows, const Params& p) {
    Binner binner;
    binner.fit(ds, rows, p.maxBins, p.seed);
    std::vector<uint8_t> B = binMatrix(ds, binner);
    const size_t d = ds.d;
    gainImportance.assign(d, 0);
    trees.clear();

    long nPos = 0;
    for (size_t r : rows) nPos += ds.y[r];
    long nNeg = static_cast<long>(rows.size()) - nPos;
    double wPos = 1, wNeg = 1;
    if (p.balanced && nPos && nNeg) {
        wPos = rows.size() / (2.0 * nPos);
        wNeg = rows.size() / (2.0 * nNeg);
    }
    double prior = (nPos * wPos) / (nPos * wPos + nNeg * wNeg);
    baseScore = std::log(prior / (1 - prior));

    std::vector<double> margin(ds.n, baseScore), g(ds.n), h(ds.n);
    std::mt19937 rng(p.seed);
    std::uniform_real_distribution<double> U(0, 1);

    for (int t = 0; t < p.nTrees; ++t) {
        for (size_t r : rows) {
            double pr = sigmoid(margin[r]);
            double w = ds.y[r] ? wPos : wNeg;
            g[r] = (pr - ds.y[r]) * w;
            h[r] = std::max(pr * (1 - pr), 1e-6) * w;
        }
        std::vector<uint32_t> sampleRows;
        for (size_t r : rows)
            if (U(rng) < p.rowSample) sampleRows.push_back(static_cast<uint32_t>(r));
        std::vector<size_t> cols;
        for (size_t f = 0; f < d; ++f)
            if (U(rng) < p.colSample) cols.push_back(f);
        if (cols.empty()) cols.push_back(rng() % d);

        std::vector<TreeNode> nodes;
        std::function<int(std::vector<uint32_t>&, int)> build = [&](std::vector<uint32_t>& rs, int depth) -> int {
            double G = 0, H = 0;
            for (auto r : rs) { G += g[r]; H += h[r]; }
            int id = static_cast<int>(nodes.size());
            nodes.emplace_back();
            nodes[id].value = static_cast<float>(-G / (H + p.lambda) * p.learningRate);
            if (depth >= p.maxDepth || rs.size() < static_cast<size_t>(2 * p.minSamplesLeaf)) return id;

            double parentScore = G * G / (H + p.lambda);
            double bestGain = 1e-9;
            int bestF = -1, bestBin = -1;
            std::vector<double> hg(256), hh(256);
            std::vector<long> hc(256);
            for (size_t f : cols) {
                size_t nb = binner.numBins(f);
                if (nb < 2) continue;
                std::fill(hg.begin(), hg.begin() + nb, 0);
                std::fill(hh.begin(), hh.begin() + nb, 0);
                std::fill(hc.begin(), hc.begin() + nb, 0);
                for (auto r : rs) {
                    uint8_t b = B[r * d + f];
                    hg[b] += g[r]; hh[b] += h[r]; hc[b]++;
                }
                double GL = 0, HL = 0;
                long CL = 0;
                for (size_t b = 0; b + 1 < nb; ++b) {
                    GL += hg[b]; HL += hh[b]; CL += hc[b];
                    long CR = static_cast<long>(rs.size()) - CL;
                    if (CL < p.minSamplesLeaf || CR < p.minSamplesLeaf) continue;
                    double GR = G - GL, HR = H - HL;
                    if (HL < p.minChildWeight || HR < p.minChildWeight) continue;
                    double gain = GL * GL / (HL + p.lambda) + GR * GR / (HR + p.lambda) - parentScore;
                    if (gain > bestGain) { bestGain = gain; bestF = static_cast<int>(f); bestBin = static_cast<int>(b); }
                }
            }
            if (bestF < 0) return id;
            std::vector<uint32_t> L, R;
            for (auto r : rs) (B[r * d + bestF] <= bestBin ? L : R).push_back(r);
            gainImportance[bestF] += bestGain;
            nodes[id].feature = bestF;
            nodes[id].threshold = binner.edges[bestF][bestBin];
            std::vector<uint32_t>().swap(rs);
            int li = build(L, depth + 1);
            int ri = build(R, depth + 1);
            nodes[id].left = li;
            nodes[id].right = ri;
            return id;
        };
        build(sampleRows, 0);
        for (size_t r : rows) {
            int i = 0;
            while (nodes[i].feature >= 0) i = ds.row(r)[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
            margin[r] += nodes[i].value;
        }
        trees.push_back(std::move(nodes));
    }
    double tot = std::accumulate(gainImportance.begin(), gainImportance.end(), 0.0);
    if (tot > 0) for (auto& v : gainImportance) v /= tot;
}

double GradientBoostedTrees::predictMargin(const float* x) const {
    double m = baseScore;
    for (auto& nodes : trees) {
        int i = 0;
        while (nodes[i].feature >= 0) i = x[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
        m += nodes[i].value;
    }
    return m;
}

std::vector<double> GradientBoostedTrees::contributions(const float* x, size_t d) const {
    std::vector<double> c(d, 0);
    for (auto& nodes : trees) {
        int i = 0;
        while (nodes[i].feature >= 0) {
            int next = x[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
            c[nodes[i].feature] += nodes[next].value - nodes[i].value;
            i = next;
        }
    }
    return c;
}

json GradientBoostedTrees::toJson() const {
    json t = json::array();
    for (auto& nodes : trees) t.push_back(nodesToJson(nodes, true, false));
    return json{{"baseScore", baseScore}, {"trees", t}, {"importance", gainImportance}};
}

GradientBoostedTrees GradientBoostedTrees::fromJson(const json& j) {
    GradientBoostedTrees m;
    m.baseScore = j.at("baseScore").get<double>();
    for (auto& t : j.at("trees")) m.trees.push_back(nodesFromJson(t));
    if (j.contains("importance")) m.gainImportance = j["importance"].get<std::vector<double>>();
    return m;
}

// ---------------------------------------------------------- RandomForest --
void RandomForest::fit(const DenseDataset& ds, const std::vector<size_t>& rows, int k, const Params& p) {
    nClasses = k;
    Binner binner;
    binner.fit(ds, rows, p.maxBins, p.seed);
    std::vector<uint8_t> B = binMatrix(ds, binner);
    const size_t d = ds.d;
    std::vector<double> classW(k, 1.0);
    if (p.balanced) {
        std::vector<long> cnt(k, 0);
        for (size_t r : rows) cnt[ds.y[r]]++;
        for (int c = 0; c < k; ++c)
            classW[c] = cnt[c] ? std::min(50.0, rows.size() / (static_cast<double>(k) * cnt[c])) : 1.0;
    }
    int mtry = p.featureFrac > 0 ? std::max(1, static_cast<int>(d * p.featureFrac))
                                 : std::max(1, static_cast<int>(std::sqrt(static_cast<double>(d))));
    trees.assign(p.nTrees, {});
    std::vector<std::vector<double>> imp(p.nTrees, std::vector<double>(d, 0));

    auto growTree = [&](int t) {
        std::mt19937 rng(p.seed * 1000 + t);
        std::uniform_int_distribution<size_t> pick(0, rows.size() - 1);
        size_t m = static_cast<size_t>(rows.size() * p.sampleFrac);
        std::vector<uint32_t> sample(m);
        for (auto& s : sample) s = static_cast<uint32_t>(rows[pick(rng)]);
        std::vector<TreeNode>& nodes = trees[t];
        std::vector<size_t> allF(d);
        std::iota(allF.begin(), allF.end(), 0);
        std::vector<double> hist;

        std::function<int(std::vector<uint32_t>&, int)> build = [&](std::vector<uint32_t>& rs, int depth) -> int {
            std::vector<double> cc(k, 0);
            for (auto r : rs) cc[ds.y[r]] += classW[ds.y[r]];
            double tot = std::accumulate(cc.begin(), cc.end(), 0.0);
            int id = static_cast<int>(nodes.size());
            nodes.emplace_back();
            auto makeLeaf = [&]() {
                nodes[id].dist.resize(k);
                for (int c = 0; c < k; ++c) nodes[id].dist[c] = static_cast<float>(tot > 0 ? cc[c] / tot : 1.0 / k);
                return id;
            };
            int nonZero = 0;
            for (double v : cc) nonZero += v > 0;
            if (nonZero <= 1 || depth >= p.maxDepth || rs.size() < static_cast<size_t>(2 * p.minSamplesLeaf)) return makeLeaf();

            double giniParent = 1;
            for (double v : cc) giniParent -= (v / tot) * (v / tot);
            double bestGain = 1e-9;
            int bestF = -1, bestBin = -1;
            std::shuffle(allF.begin(), allF.end(), rng);
            for (int fi = 0; fi < mtry; ++fi) {
                size_t f = allF[fi];
                size_t nb = binner.numBins(f);
                if (nb < 2) continue;
                hist.assign(nb * k, 0);
                std::vector<long> hc(nb, 0);
                for (auto r : rs) {
                    uint8_t b = B[r * d + f];
                    hist[b * k + ds.y[r]] += classW[ds.y[r]];
                    hc[b]++;
                }
                std::vector<double> left(k, 0);
                long cl = 0;
                for (size_t b = 0; b + 1 < nb; ++b) {
                    for (int c = 0; c < k; ++c) left[c] += hist[b * k + c];
                    cl += hc[b];
                    long cr = static_cast<long>(rs.size()) - cl;
                    if (cl < p.minSamplesLeaf || cr < p.minSamplesLeaf) continue;
                    double lt = std::accumulate(left.begin(), left.end(), 0.0), rt = tot - lt;
                    if (lt <= 0 || rt <= 0) continue;
                    double gl = 1, gr = 1;
                    for (int c = 0; c < k; ++c) {
                        gl -= (left[c] / lt) * (left[c] / lt);
                        double rc = cc[c] - left[c];
                        gr -= (rc / rt) * (rc / rt);
                    }
                    double gain = giniParent - (lt / tot) * gl - (rt / tot) * gr;
                    if (gain > bestGain) { bestGain = gain; bestF = static_cast<int>(f); bestBin = static_cast<int>(b); }
                }
            }
            if (bestF < 0) return makeLeaf();
            std::vector<uint32_t> L, R;
            for (auto r : rs) (B[r * d + bestF] <= bestBin ? L : R).push_back(r);
            imp[t][bestF] += bestGain * tot;
            nodes[id].feature = bestF;
            nodes[id].threshold = binner.edges[bestF][bestBin];
            std::vector<uint32_t>().swap(rs);
            int li = build(L, depth + 1);
            int ri = build(R, depth + 1);
            nodes[id].left = li;
            nodes[id].right = ri;
            return id;
        };
        build(sample, 0);
    };

    int nThreads = std::max(1, p.threads);
    std::vector<std::thread> pool;
    for (int w = 0; w < nThreads; ++w)
        pool.emplace_back([&, w]() {
            for (int t = w; t < p.nTrees; t += nThreads) growTree(t);
        });
    for (auto& th : pool) th.join();

    gainImportance.assign(d, 0);
    for (auto& v : imp)
        for (size_t f = 0; f < d; ++f) gainImportance[f] += v[f];
    double tot = std::accumulate(gainImportance.begin(), gainImportance.end(), 0.0);
    if (tot > 0) for (auto& v : gainImportance) v /= tot;
}

std::vector<double> RandomForest::predictProba(const float* x) const {
    std::vector<double> p(nClasses, 0);
    for (auto& nodes : trees) {
        int i = 0;
        while (nodes[i].feature >= 0) i = x[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
        for (int c = 0; c < nClasses && c < static_cast<int>(nodes[i].dist.size()); ++c) p[c] += nodes[i].dist[c];
    }
    for (auto& v : p) v /= std::max<size_t>(trees.size(), 1);
    return p;
}

int RandomForest::predict(const float* x) const {
    auto p = predictProba(x);
    return static_cast<int>(std::max_element(p.begin(), p.end()) - p.begin());
}

json RandomForest::toJson() const {
    json t = json::array();
    for (auto& nodes : trees) t.push_back(nodesToJson(nodes, false, true));
    return json{{"nClasses", nClasses}, {"trees", t}, {"importance", gainImportance}};
}

RandomForest RandomForest::fromJson(const json& j) {
    RandomForest m;
    m.nClasses = j.at("nClasses").get<int>();
    for (auto& t : j.at("trees")) m.trees.push_back(nodesFromJson(t));
    if (j.contains("importance")) m.gainImportance = j["importance"].get<std::vector<double>>();
    return m;
}

// ------------------------------------------------------- IsolationForest --
static double cFactor(double n) {
    if (n <= 1) return 0;
    if (n == 2) return 1;
    return 2.0 * (std::log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n;
}

void IsolationForest::fit(const DenseDataset& ds, const std::vector<size_t>& rows, const Params& p) {
    sampleSize = std::min<int>(p.sampleSize, static_cast<int>(rows.size()));
    int maxDepth = static_cast<int>(std::ceil(std::log2(std::max(2, sampleSize))));
    trees.clear();
    std::mt19937 rng(p.seed);
    for (int t = 0; t < p.nTrees; ++t) {
        std::vector<size_t> sample(rows);
        std::shuffle(sample.begin(), sample.end(), rng);
        sample.resize(sampleSize);
        std::vector<INode> nodes;
        std::function<int(std::vector<size_t>&, int)> build = [&](std::vector<size_t>& rs, int depth) -> int {
            int id = static_cast<int>(nodes.size());
            nodes.emplace_back();
            nodes[id].size = static_cast<int>(rs.size());
            if (depth >= maxDepth || rs.size() <= 1) return id;
            // try a few features until one has spread
            for (int attempt = 0; attempt < 8; ++attempt) {
                size_t f = rng() % ds.d;
                float lo = ds.row(rs[0])[f], hi = lo;
                for (auto r : rs) { lo = std::min(lo, ds.row(r)[f]); hi = std::max(hi, ds.row(r)[f]); }
                if (hi <= lo) continue;
                std::uniform_real_distribution<float> U(lo, hi);
                float thr = U(rng);
                std::vector<size_t> L, R;
                for (auto r : rs) (ds.row(r)[f] <= thr ? L : R).push_back(r);
                if (L.empty() || R.empty()) continue;
                nodes[id].feature = static_cast<int>(f);
                nodes[id].threshold = thr;
                int li = build(L, depth + 1);
                int ri = build(R, depth + 1);
                nodes[id].left = li;
                nodes[id].right = ri;
                return id;
            }
            return id;
        };
        build(sample, 0);
        trees.push_back(std::move(nodes));
    }
    useEnvelope = p.useEnvelope;
    envLo.assign(ds.d, 0); envHi.assign(ds.d, 0); envScale.assign(ds.d, 1);
    if (useEnvelope) {
        std::vector<float> v(rows.size());
        for (size_t f = 0; f < ds.d; ++f) {
            for (size_t k = 0; k < rows.size(); ++k) v[k] = ds.row(rows[k])[f];
            std::sort(v.begin(), v.end());
            auto q = [&](double p) { return v[std::min(v.size() - 1, static_cast<size_t>(p * (v.size() - 1)))]; };
            envLo[f] = q(p.envelopeQuantile);
            envHi[f] = q(1.0 - p.envelopeQuantile);
            float iqr = q(0.75) - q(0.25);
            envScale[f] = std::max({iqr, (envHi[f] - envLo[f]) / 4.0f, 1e-3f});
        }
    }
    std::vector<double> scores;
    for (size_t r : rows) scores.push_back(score(ds.row(r)));
    std::sort(scores.begin(), scores.end());
    threshold = scores[std::min(scores.size() - 1, static_cast<size_t>(scores.size() * (1.0 - p.contamination)))];
}

double IsolationForest::envelopeScore(const float* x, int* worst) const {
    if (!useEnvelope || envLo.empty()) return 0;
    double maxExcess = 0;
    int wf = -1;
    for (size_t f = 0; f < envLo.size(); ++f) {
        double e = 0;
        // Upper side only: for security telemetry "more than ever seen" (more
        // failed logins, ports, bytes, encoded commands...) is the risk signal;
        // "fewer than usual" is not.
        if (x[f] > envHi[f]) e = (x[f] - envHi[f]) / envScale[f];
        if (e > maxExcess) { maxExcess = e; wf = static_cast<int>(f); }
    }
    if (worst) *worst = wf;
    return 1.0 - std::exp(-maxExcess / 2.0);
}

double IsolationForest::score(const float* x) const {
    double s = isolationScore(x);
    double e = envelopeScore(x);
    return e > 0 ? std::max(s, 0.5 + 0.5 * e) : s;
}

double IsolationForest::isolationScore(const float* x) const {
    double total = 0;
    for (auto& nodes : trees) {
        int i = 0, depth = 0;
        while (nodes[i].feature >= 0) {
            i = x[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
            ++depth;
        }
        total += depth + cFactor(nodes[i].size);
    }
    double avg = total / std::max<size_t>(trees.size(), 1);
    return std::pow(2.0, -avg / cFactor(sampleSize));
}

std::vector<double> IsolationForest::isolationContributions(const float* x, size_t d) const {
    // Features that separate the point close to the root get more credit.
    std::vector<double> c(d, 0);
    for (auto& nodes : trees) {
        int i = 0, depth = 0;
        while (nodes[i].feature >= 0) {
            c[nodes[i].feature] += 1.0 / (1 + depth);
            i = x[nodes[i].feature] <= nodes[i].threshold ? nodes[i].left : nodes[i].right;
            ++depth;
        }
    }
    double tot = std::accumulate(c.begin(), c.end(), 0.0);
    if (tot > 0) for (auto& v : c) v /= tot;
    return c;
}

json IsolationForest::toJson() const {
    json t = json::array();
    for (auto& nodes : trees) {
        std::vector<int> f, l, r, s;
        std::vector<float> th;
        for (auto& n : nodes) {
            f.push_back(n.feature); th.push_back(n.threshold); l.push_back(n.left); r.push_back(n.right); s.push_back(n.size);
        }
        t.push_back({{"f", f}, {"t", th}, {"l", l}, {"r", r}, {"s", s}});
    }
    json j{{"sampleSize", sampleSize}, {"threshold", threshold}, {"trees", t}, {"useEnvelope", useEnvelope}};
    if (useEnvelope) { j["envLo"] = envLo; j["envHi"] = envHi; j["envScale"] = envScale; }
    return j;
}

IsolationForest IsolationForest::fromJson(const json& j) {
    IsolationForest m;
    m.sampleSize = j.at("sampleSize").get<int>();
    m.threshold = j.at("threshold").get<double>();
    m.useEnvelope = j.value("useEnvelope", false);
    if (m.useEnvelope) {
        m.envLo = j.at("envLo").get<std::vector<float>>();
        m.envHi = j.at("envHi").get<std::vector<float>>();
        m.envScale = j.at("envScale").get<std::vector<float>>();
    }
    for (auto& t : j.at("trees")) {
        auto f = t.at("f").get<std::vector<int>>();
        auto th = t.at("t").get<std::vector<float>>();
        auto l = t.at("l").get<std::vector<int>>();
        auto r = t.at("r").get<std::vector<int>>();
        auto s = t.at("s").get<std::vector<int>>();
        std::vector<INode> nodes(f.size());
        for (size_t i = 0; i < f.size(); ++i) nodes[i] = {f[i], th[i], l[i], r[i], s[i]};
        m.trees.push_back(std::move(nodes));
    }
    return m;
}

}  // namespace cyberguard::ml
