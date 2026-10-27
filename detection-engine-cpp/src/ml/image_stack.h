#pragma once
// Shared by the trainer and the model registry: turns per-block manipulation
// probabilities into image-level evidence for the stacked image model.
#include <algorithm>
#include <numeric>
#include <vector>

#include "../features/media_features.h"
#include "tree_models.h"

namespace cyberguard::ml {

inline std::vector<float> aggregateImageBlocks(const std::vector<double>& s, const std::vector<features::BlockFeatures>& blocks,
                                               float globalProb) {
    if (s.empty()) return {globalProb, 0, 0, 0, 0, 0, 0, 0};
    int maxX = 0, maxY = 0;
    for (auto& b : blocks) { maxX = std::max(maxX, b.x); maxY = std::max(maxY, b.y); }
    int bw = maxX / 32 + 1, bh = maxY / 32 + 1;
    std::vector<double> grid(static_cast<size_t>(bw) * bh, 0);
    for (size_t i = 0; i < blocks.size(); ++i) grid[static_cast<size_t>(blocks[i].y / 32) * bw + blocks[i].x / 32] = s[i];
    double best2x2 = 0;
    for (int y = 0; y + 1 < bh; ++y)
        for (int x = 0; x + 1 < bw; ++x)
            best2x2 = std::max(best2x2, (grid[y * bw + x] + grid[y * bw + x + 1] + grid[(y + 1) * bw + x] + grid[(y + 1) * bw + x + 1]) / 4);
    std::vector<double> sorted(s);
    std::sort(sorted.rbegin(), sorted.rend());
    auto topMean = [&](size_t k) { k = std::min(k, sorted.size()); return std::accumulate(sorted.begin(), sorted.begin() + k, 0.0) / k; };
    double mean = std::accumulate(s.begin(), s.end(), 0.0) / s.size();
    double f5 = 0, f9 = 0;
    for (double v : s) { f5 += v > 0.5; f9 += v > 0.9; }
    return {globalProb, static_cast<float>(sorted[0]), static_cast<float>(topMean(2)), static_cast<float>(topMean(4)),
            static_cast<float>(mean), static_cast<float>(f5 / s.size()), static_cast<float>(f9 / s.size()), static_cast<float>(best2x2)};
}

inline std::vector<float> aggregateImageBlocks(const GradientBoostedTrees& m, const std::vector<features::BlockFeatures>& blocks,
                                               float globalProb) {
    std::vector<double> s;
    for (auto& b : blocks) s.push_back(m.predictProba(b.f.data()));
    return aggregateImageBlocks(s, blocks, globalProb);
}

}  // namespace cyberguard::ml
