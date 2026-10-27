#include "media_features.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <array>
#include <numeric>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_GIF
#define STBI_NO_PSD
#define STBI_NO_PIC
#define STBI_NO_PNM
#define STBI_NO_HDR
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

namespace cyberguard::features {

static const double PI = 3.14159265358979323846;

void fft(std::vector<std::complex<double>>& a, bool inverse) {
    size_t n = a.size();
    for (size_t i = 1, j = 0; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    for (size_t len = 2; len <= n; len <<= 1) {
        double ang = 2 * PI / len * (inverse ? 1 : -1);
        std::complex<double> wl(std::cos(ang), std::sin(ang));
        for (size_t i = 0; i < n; i += len) {
            std::complex<double> w(1);
            for (size_t k = 0; k < len / 2; ++k) {
                auto u = a[i + k], v = a[i + k + len / 2] * w;
                a[i + k] = u + v;
                a[i + k + len / 2] = u - v;
                w *= wl;
            }
        }
    }
    if (inverse)
        for (auto& x : a) x /= static_cast<double>(n);
}

// ================================================================ IMAGE ==
bool decodeImage(const std::string& bytes, RgbImage& out) {
    int w, h, c;
    unsigned char* data = stbi_load_from_memory(reinterpret_cast<const stbi_uc*>(bytes.data()),
                                                static_cast<int>(bytes.size()), &w, &h, &c, 3);
    if (!data) return false;
    out.w = w;
    out.h = h;
    out.px.assign(data, data + static_cast<size_t>(w) * h * 3);
    stbi_image_free(data);
    return true;
}

static void writeToString(void* ctx, void* data, int size) {
    static_cast<std::string*>(ctx)->append(static_cast<char*>(data), size);
}

std::string encodeJpeg(const RgbImage& img, int quality) {
    std::string out;
    stbi_write_jpg_to_func(writeToString, &out, img.w, img.h, 3, img.px.data(), quality);
    return out;
}

RgbImage cropAt(const RgbImage& img, int x, int y, int w, int h) {
    RgbImage o;
    x = std::clamp(x, 0, std::max(0, img.w - 1));
    y = std::clamp(y, 0, std::max(0, img.h - 1));
    w = std::min(w, img.w - x);
    h = std::min(h, img.h - y);
    o.w = w;
    o.h = h;
    o.px.resize(static_cast<size_t>(w) * h * 3);
    for (int r = 0; r < h; ++r)
        std::memcpy(&o.px[static_cast<size_t>(r) * w * 3], &img.px[(static_cast<size_t>(y + r) * img.w + x) * 3], static_cast<size_t>(w) * 3);
    return o;
}

RgbImage cropCenter(const RgbImage& img, int maxSide) {
    if (img.w <= maxSide && img.h <= maxSide) return img;
    int w = std::min(img.w, maxSide), h = std::min(img.h, maxSide);
    return cropAt(img, (img.w - w) / 2, (img.h - h) / 2, w, h);
}

RgbImage resizeBilinear(const RgbImage& img, int w, int h) {
    RgbImage o;
    o.w = w;
    o.h = h;
    o.px.resize(static_cast<size_t>(w) * h * 3);
    for (int y = 0; y < h; ++y) {
        double sy = (y + 0.5) * img.h / h - 0.5;
        int y0 = std::clamp(static_cast<int>(std::floor(sy)), 0, img.h - 1), y1 = std::min(y0 + 1, img.h - 1);
        double fy = std::clamp(sy - y0, 0.0, 1.0);
        for (int x = 0; x < w; ++x) {
            double sx = (x + 0.5) * img.w / w - 0.5;
            int x0 = std::clamp(static_cast<int>(std::floor(sx)), 0, img.w - 1), x1 = std::min(x0 + 1, img.w - 1);
            double fx = std::clamp(sx - x0, 0.0, 1.0);
            for (int c = 0; c < 3; ++c) {
                auto P = [&](int xx, int yy) { return img.px[(static_cast<size_t>(yy) * img.w + xx) * 3 + c]; };
                double v = (1 - fx) * (1 - fy) * P(x0, y0) + fx * (1 - fy) * P(x1, y0) + (1 - fx) * fy * P(x0, y1) + fx * fy * P(x1, y1);
                o.px[(static_cast<size_t>(y) * w + x) * 3 + c] = static_cast<uint8_t>(std::clamp(v + 0.5, 0.0, 255.0));
            }
        }
    }
    return o;
}

const std::vector<std::string>& imageFeatureNames() {
    static const std::vector<std::string> n = {
        "ela_mean", "ela_block_std", "ela_block_max_ratio", "ela_mean_q70", "noise_residual_var",
        "noise_block_cv", "noise_block_max_ratio", "jpeg_blockiness", "hf_energy_ratio", "spectral_slope",
        "spectral_peakiness", "saturation_mean", "saturation_std", "residual_corr_rg", "residual_corr_rb",
        "residual_corr_gb", "edge_density", "luminance_std", "clipped_ratio", "ela_noise_ratio"};
    return n;
}

static std::vector<double> luminance(const RgbImage& img) {
    std::vector<double> y(static_cast<size_t>(img.w) * img.h);
    for (size_t i = 0; i < y.size(); ++i)
        y[i] = 0.299 * img.px[i * 3] + 0.587 * img.px[i * 3 + 1] + 0.114 * img.px[i * 3 + 2];
    return y;
}

static void blockStats(const std::vector<double>& m, int w, int h, int bs, double& mean, double& stdv, double& maxRatio,
                       double& cv) {
    std::vector<double> blocks;
    for (int by = 0; by + bs <= h; by += bs)
        for (int bx = 0; bx + bs <= w; bx += bs) {
            double s = 0;
            for (int y = by; y < by + bs; ++y)
                for (int x = bx; x < bx + bs; ++x) s += m[static_cast<size_t>(y) * w + x];
            blocks.push_back(s / (bs * bs));
        }
    if (blocks.empty()) { mean = stdv = maxRatio = cv = 0; return; }
    mean = std::accumulate(blocks.begin(), blocks.end(), 0.0) / blocks.size();
    double v = 0;
    for (double b : blocks) v += (b - mean) * (b - mean);
    stdv = std::sqrt(v / blocks.size());
    maxRatio = mean > 1e-9 ? *std::max_element(blocks.begin(), blocks.end()) / mean : 0;
    cv = mean > 1e-9 ? stdv / mean : 0;
}

static double pearson(const std::vector<double>& a, const std::vector<double>& b) {
    double ma = std::accumulate(a.begin(), a.end(), 0.0) / a.size(), mb = std::accumulate(b.begin(), b.end(), 0.0) / b.size();
    double sab = 0, saa = 0, sbb = 0;
    for (size_t i = 0; i < a.size(); ++i) { sab += (a[i] - ma) * (b[i] - mb); saa += (a[i] - ma) * (a[i] - ma); sbb += (b[i] - mb) * (b[i] - mb); }
    return (saa > 0 && sbb > 0) ? sab / std::sqrt(saa * sbb) : 0;
}

std::vector<float> imageFeatures(const RgbImage& input) {
    RgbImage img = cropCenter(input, 512);
    const int w = img.w, h = img.h;
    if (w < 32 || h < 32) return std::vector<float>(imageFeatureNames().size(), 0.0f);
    const size_t N = static_cast<size_t>(w) * h;

    // --- Error level analysis at q90 and q70
    auto elaAt = [&](int q, std::vector<double>& ela) {
        RgbImage re;
        decodeImage(encodeJpeg(img, q), re);
        ela.assign(N, 0);
        if (re.w != w || re.h != h) return 0.0;
        double s = 0;
        for (size_t i = 0; i < N; ++i) {
            double d = (std::abs(img.px[i * 3] - re.px[i * 3]) + std::abs(img.px[i * 3 + 1] - re.px[i * 3 + 1]) +
                        std::abs(img.px[i * 3 + 2] - re.px[i * 3 + 2])) / 3.0;
            ela[i] = d;
            s += d;
        }
        return s / N;
    };
    std::vector<double> ela, ela70;
    double elaMean = elaAt(90, ela);
    double elaMean70 = elaAt(70, ela70);
    double eM, eStd, eMax, eCv;
    blockStats(ela, w, h, 16, eM, eStd, eMax, eCv);

    // --- Noise residual (Laplacian high-pass on luminance)
    std::vector<double> Y = luminance(img), res(N, 0), res2(N, 0);
    for (int y = 1; y < h - 1; ++y)
        for (int x = 1; x < w - 1; ++x) {
            size_t i = static_cast<size_t>(y) * w + x;
            double r = 4 * Y[i] - Y[i - 1] - Y[i + 1] - Y[i - w] - Y[i + w];
            res[i] = r;
            res2[i] = r * r;
        }
    double nM, nStd, nMax, nCv;
    blockStats(res2, w, h, 32, nM, nStd, nMax, nCv);
    double noiseVar = std::accumulate(res2.begin(), res2.end(), 0.0) / N;

    // --- JPEG 8x8 blockiness: gradient at block boundaries vs inside
    double onB = 0, offB = 0;
    long cOn = 0, cOff = 0;
    for (int y = 0; y < h; ++y)
        for (int x = 1; x < w; ++x) {
            double d = std::fabs(Y[static_cast<size_t>(y) * w + x] - Y[static_cast<size_t>(y) * w + x - 1]);
            if (x % 8 == 0) { onB += d; cOn++; } else { offB += d; cOff++; }
        }
    double blockiness = (cOn && cOff && offB > 0) ? (onB / cOn) / (offB / cOff) : 1.0;

    // --- Frequency spectrum of a 256x256 luminance crop
    int S = 256;
    while (S > std::min(w, h)) S >>= 1;
    int ox = (w - S) / 2, oy = (h - S) / 2;
    std::vector<std::vector<std::complex<double>>> F(S, std::vector<std::complex<double>>(S));
    for (int y = 0; y < S; ++y) {
        for (int x = 0; x < S; ++x) {
            double win = (0.5 - 0.5 * std::cos(2 * PI * x / (S - 1))) * (0.5 - 0.5 * std::cos(2 * PI * y / (S - 1)));
            F[y][x] = Y[static_cast<size_t>(y + oy) * w + x + ox] * win;
        }
        fft(F[y], false);
    }
    for (int x = 0; x < S; ++x) {
        std::vector<std::complex<double>> col(S);
        for (int y = 0; y < S; ++y) col[y] = F[y][x];
        fft(col, false);
        for (int y = 0; y < S; ++y) F[y][x] = col[y];
    }
    int nR = S / 2;
    std::vector<double> radial(nR, 0), radialCnt(nR, 0);
    double total = 0, high = 0;
    std::vector<double> outer;
    for (int y = 0; y < S; ++y)
        for (int x = 0; x < S; ++x) {
            int fy = y < S / 2 ? y : y - S, fx = x < S / 2 ? x : x - S;
            double r = std::sqrt(static_cast<double>(fx * fx + fy * fy));
            double p = std::norm(F[y][x]);
            if (r < 1) continue;
            total += p;
            if (r > 0.5 * nR) high += p;
            int ri = static_cast<int>(r);
            if (ri < nR) { radial[ri] += p; radialCnt[ri]++; }
            if (r > 0.35 * nR && std::abs(fx) > 2 && std::abs(fy) > 2) outer.push_back(p);
        }
    // spectral slope: fit log(power) vs log(freq)
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    int cnt = 0;
    for (int r = 2; r < nR; ++r) {
        if (radialCnt[r] == 0) continue;
        double lx = std::log(r), ly = std::log(radial[r] / radialCnt[r] + 1e-9);
        sx += lx; sy += ly; sxx += lx * lx; sxy += lx * ly; cnt++;
    }
    double slope = cnt > 2 ? (cnt * sxy - sx * sy) / (cnt * sxx - sx * sx) : 0;
    double peakiness = 0;
    if (!outer.empty()) {
        std::nth_element(outer.begin(), outer.begin() + outer.size() / 2, outer.end());
        double med = outer[outer.size() / 2];
        double mx = *std::max_element(outer.begin(), outer.end());
        peakiness = med > 0 ? std::log10(mx / med) : 0;
    }

    // --- Colour statistics
    double satSum = 0, satSq = 0;
    long clipped = 0;
    for (size_t i = 0; i < N; ++i) {
        int r = img.px[i * 3], g = img.px[i * 3 + 1], b = img.px[i * 3 + 2];
        int mx = std::max({r, g, b}), mn = std::min({r, g, b});
        double s = mx > 0 ? static_cast<double>(mx - mn) / mx : 0;
        satSum += s;
        satSq += s * s;
        if (mx == 255 || mn == 0) clipped++;
    }
    double satMean = satSum / N, satStd = std::sqrt(std::max(0.0, satSq / N - satMean * satMean));

    // residual correlations between colour channels (demosaicing traces)
    std::vector<double> rr, rg, rb;
    for (int y = 1; y < h - 1; y += 2)
        for (int x = 1; x < w - 1; x += 2) {
            size_t i = static_cast<size_t>(y) * w + x;
            auto hp = [&](int c) {
                return 4.0 * img.px[i * 3 + c] - img.px[(i - 1) * 3 + c] - img.px[(i + 1) * 3 + c] -
                       img.px[(i - w) * 3 + c] - img.px[(i + w) * 3 + c];
            };
            rr.push_back(hp(0)); rg.push_back(hp(1)); rb.push_back(hp(2));
        }

    // edge density (Sobel)
    long edges = 0;
    for (int y = 1; y < h - 1; ++y)
        for (int x = 1; x < w - 1; ++x) {
            size_t i = static_cast<size_t>(y) * w + x;
            double gx = Y[i - w + 1] + 2 * Y[i + 1] + Y[i + w + 1] - Y[i - w - 1] - 2 * Y[i - 1] - Y[i + w - 1];
            double gy = Y[i + w - 1] + 2 * Y[i + w] + Y[i + w + 1] - Y[i - w - 1] - 2 * Y[i - w] - Y[i - w + 1];
            if (std::sqrt(gx * gx + gy * gy) > 100) edges++;
        }
    double lm = std::accumulate(Y.begin(), Y.end(), 0.0) / N, lv = 0;
    for (double v : Y) lv += (v - lm) * (v - lm);

    return {static_cast<float>(elaMean), static_cast<float>(eStd), static_cast<float>(eMax),
            static_cast<float>(elaMean70), static_cast<float>(std::log1p(noiseVar)), static_cast<float>(nCv),
            static_cast<float>(nMax), static_cast<float>(blockiness), static_cast<float>(total > 0 ? high / total : 0),
            static_cast<float>(slope), static_cast<float>(peakiness), static_cast<float>(satMean),
            static_cast<float>(satStd), static_cast<float>(pearson(rr, rg)), static_cast<float>(pearson(rr, rb)),
            static_cast<float>(pearson(rg, rb)), static_cast<float>(static_cast<double>(edges) / N),
            static_cast<float>(std::sqrt(lv / N)), static_cast<float>(static_cast<double>(clipped) / N),
            static_cast<float>(elaMean / (std::sqrt(noiseVar) + 1e-6))};
}

const std::vector<std::string>& imageBlockFeatureNames() {
    static const std::vector<std::string> n = {
        "ela90_log_ratio", "ela70_log_ratio", "noise_log_ratio", "gradient_log_ratio", "ela90_robust_z",
        "noise_robust_z", "blockgrid_log_ratio", "saturation_diff", "ela_to_noise_log_ratio", "ela90_abs",
        "noise_abs_log", "luminance_mean", "neighbour_ela_log_ratio", "neighbour_noise_log_ratio",
        "dct_quant_residual_ratio", "dct_quant_residual_z", "dct_shifted_grid_residual_ratio", "dct_hf_energy_log_ratio"};
    return n;
}

// 8x8 DCT-II on a luminance tile.
static void dct8(const double in[64], double out[64]) {
    static double C[8][8];
    static bool init = false;
    if (!init) {
        for (int u = 0; u < 8; ++u)
            for (int x = 0; x < 8; ++x) C[u][x] = (u == 0 ? std::sqrt(0.125) : 0.5) * std::cos((2 * x + 1) * u * PI / 16);
        init = true;
    }
    double tmp[64];
    for (int y = 0; y < 8; ++y)
        for (int u = 0; u < 8; ++u) { double s = 0; for (int x = 0; x < 8; ++x) s += C[u][x] * in[y * 8 + x]; tmp[y * 8 + u] = s; }
    for (int u = 0; u < 8; ++u)
        for (int v = 0; v < 8; ++v) { double s = 0; for (int y = 0; y < 8; ++y) s += C[v][y] * tmp[y * 8 + u]; out[v * 8 + u] = s; }
}

// Per 8x8 block: how far low-frequency DCT coefficients are from multiples of
// the image's dominant quantisation step (estimated per frequency).
static std::vector<double> dctQuantResidual(const std::vector<double>& Y, int w, int h, int off, std::vector<double>* hfOut) {
    const int freqs[9][2] = {{0, 1}, {1, 0}, {1, 1}, {0, 2}, {2, 0}, {1, 2}, {2, 1}, {2, 2}, {0, 3}};
    int bw = (w - off) / 8, bh = (h - off) / 8;
    std::vector<std::array<double, 9>> coef(static_cast<size_t>(bw) * bh);
    std::vector<double> hf(static_cast<size_t>(bw) * bh, 0);
    double in[64], out[64];
    for (int by = 0; by < bh; ++by)
        for (int bx = 0; bx < bw; ++bx) {
            for (int y = 0; y < 8; ++y)
                for (int x = 0; x < 8; ++x) in[y * 8 + x] = Y[static_cast<size_t>(off + by * 8 + y) * w + off + bx * 8 + x] - 128;
            dct8(in, out);
            for (int k = 0; k < 9; ++k) coef[static_cast<size_t>(by) * bw + bx][k] = out[freqs[k][0] * 8 + freqs[k][1]];
            double e = 0;
            for (int v = 4; v < 8; ++v) for (int u = 4; u < 8; ++u) e += out[v * 8 + u] * out[v * 8 + u];
            hf[static_cast<size_t>(by) * bw + bx] = std::log1p(e);
        }
    // dominant step per frequency: the q in [1,40] that best explains coefficients
    std::array<double, 9> step{};
    for (int k = 0; k < 9; ++k) {
        double best = 1, bestScore = -1;
        for (int q = 2; q <= 40; ++q) {
            double sc = 0; int n = 0;
            for (auto& c : coef) if (std::fabs(c[k]) > q * 0.5) { double r = c[k] / q; sc += 1 - 2 * std::fabs(r - std::round(r)); n++; }
            if (n < 20) continue;
            sc /= n;
            if (sc > bestScore + 0.02) { bestScore = sc; best = q; }
        }
        step[k] = bestScore > 0.3 ? best : 0;  // 0 => no quantisation evidence (e.g. PNG source)
    }
    std::vector<double> res(coef.size(), 0);
    for (size_t i = 0; i < coef.size(); ++i) {
        double r = 0; int n = 0;
        for (int k = 0; k < 9; ++k) {
            if (step[k] <= 0 || std::fabs(coef[i][k]) < step[k] * 0.5) continue;
            double q = coef[i][k] / step[k];
            r += 2 * std::fabs(q - std::round(q)); n++;
        }
        res[i] = n ? r / n : 0;
    }
    if (hfOut) *hfOut = hf;
    return res;
}

std::vector<BlockFeatures> imageBlockFeatures(const RgbImage& input) {
    RgbImage img = cropCenter(input, 512);
    const int w = img.w, h = img.h, bs = 32;
    std::vector<BlockFeatures> out;
    if (w < 2 * bs || h < 2 * bs) return out;
    const size_t N = static_cast<size_t>(w) * h;
    auto ela = [&](int q) {
        RgbImage re;
        decodeImage(encodeJpeg(img, q), re);
        std::vector<double> e(N, 0);
        if (re.w == w && re.h == h)
            for (size_t i = 0; i < N; ++i)
                e[i] = (std::abs(img.px[i * 3] - re.px[i * 3]) + std::abs(img.px[i * 3 + 1] - re.px[i * 3 + 1]) +
                        std::abs(img.px[i * 3 + 2] - re.px[i * 3 + 2])) / 3.0;
        return e;
    };
    std::vector<double> e90 = ela(90), e70 = ela(70), Y = luminance(img), noise(N, 0), grad(N, 0), sat(N, 0), grid(N, 0);
    for (int y = 1; y < h - 1; ++y)
        for (int x = 1; x < w - 1; ++x) {
            size_t i = static_cast<size_t>(y) * w + x;
            double r = 4 * Y[i] - Y[i - 1] - Y[i + 1] - Y[i - w] - Y[i + w];
            noise[i] = r * r;
            grad[i] = std::fabs(Y[i + 1] - Y[i - 1]) + std::fabs(Y[i + w] - Y[i - w]);
            if (x % 8 == 0) grid[i] = std::fabs(Y[i] - Y[i - 1]);
        }
    for (size_t i = 0; i < N; ++i) {
        int mx = std::max({img.px[i * 3], img.px[i * 3 + 1], img.px[i * 3 + 2]});
        int mn = std::min({img.px[i * 3], img.px[i * 3 + 1], img.px[i * 3 + 2]});
        sat[i] = mx ? static_cast<double>(mx - mn) / mx : 0;
    }
    int bw = w / bs, bh = h / bs;
    struct Raw { double e90, e70, n, g, grid, sat, lum; };
    std::vector<Raw> raw(static_cast<size_t>(bw) * bh);
    for (int by = 0; by < bh; ++by)
        for (int bx = 0; bx < bw; ++bx) {
            Raw r{0, 0, 0, 0, 0, 0, 0};
            for (int y = by * bs; y < (by + 1) * bs; ++y)
                for (int x = bx * bs; x < (bx + 1) * bs; ++x) {
                    size_t i = static_cast<size_t>(y) * w + x;
                    r.e90 += e90[i]; r.e70 += e70[i]; r.n += noise[i]; r.g += grad[i]; r.grid += grid[i]; r.sat += sat[i]; r.lum += Y[i];
                }
            double a = bs * bs;
            r.e90 /= a; r.e70 /= a; r.n /= a; r.g /= a; r.grid /= a; r.sat /= a; r.lum /= a;
            raw[static_cast<size_t>(by) * bw + bx] = r;
        }
    auto medMad = [&](auto getter, double& med, double& mad) {
        std::vector<double> v;
        for (auto& r : raw) v.push_back(getter(r));
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        med = v[v.size() / 2];
        for (auto& x : v) x = std::fabs(x - med);
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        mad = v[v.size() / 2] + 1e-6;
    };
    double mE90, dE90, mE70, dE70, mN, dN, mG, dG, mGrid, dGrid, mSat, dSat;
    medMad([](const Raw& r) { return r.e90; }, mE90, dE90);
    medMad([](const Raw& r) { return r.e70; }, mE70, dE70);
    medMad([](const Raw& r) { return std::log1p(r.n); }, mN, dN);
    medMad([](const Raw& r) { return r.g; }, mG, dG);
    medMad([](const Raw& r) { return r.grid; }, mGrid, dGrid);
    medMad([](const Raw& r) { return r.sat; }, mSat, dSat);
    auto lr = [](double a, double b) { return static_cast<float>(std::log((a + 0.05) / (b + 0.05))); };
    // DCT quantisation consistency on the aligned grid and a shifted (4,4) grid
    std::vector<double> hf8;
    std::vector<double> q0 = dctQuantResidual(Y, w, h, 0, &hf8), q4 = dctQuantResidual(Y, w, h, 4, nullptr);
    int b8w = w / 8, b8w4 = (w - 4) / 8;
    auto region = [&](const std::vector<double>& v, int stride, int bx, int by, int off) {
        double sum = 0; int n = 0;
        for (int y = by * bs + off; y + 8 <= (by + 1) * bs + off && (y - off) / 8 < static_cast<int>(v.size() / std::max(stride, 1)); y += 8)
            for (int x = bx * bs + off; x + 8 <= (bx + 1) * bs + off; x += 8) {
                size_t idx = static_cast<size_t>((y - off) / 8) * stride + (x - off) / 8;
                if (idx < v.size() && (x - off) / 8 < stride) { sum += v[idx]; n++; }
            }
        return n ? sum / n : 0.0;
    };
    std::vector<double> rq0(raw.size()), rq4(raw.size()), rhf(raw.size());
    for (int by = 0; by < bh; ++by)
        for (int bx = 0; bx < bw; ++bx) {
            size_t k = static_cast<size_t>(by) * bw + bx;
            rq0[k] = region(q0, b8w, bx, by, 0);
            rq4[k] = region(q4, b8w4, bx, by, 4);
            rhf[k] = region(hf8, b8w, bx, by, 0);
        }
    auto medMadV = [](std::vector<double> v, double& med, double& mad) {
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        med = v[v.size() / 2];
        for (auto& x : v) x = std::fabs(x - med);
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        mad = v[v.size() / 2] + 1e-3;
    };
    double mQ0, dQ0, mQ4, dQ4, mHf, dHf;
    medMadV(rq0, mQ0, dQ0); medMadV(rq4, mQ4, dQ4); medMadV(rhf, mHf, dHf);
    for (int by = 0; by < bh; ++by)
        for (int bx = 0; bx < bw; ++bx) {
            const Raw& r = raw[static_cast<size_t>(by) * bw + bx];
            double nbE = 0, nbN = 0;
            int nb = 0;
            for (int dy = -1; dy <= 1; ++dy)
                for (int dx = -1; dx <= 1; ++dx) {
                    int yy = by + dy, xx = bx + dx;
                    if ((dx || dy) && yy >= 0 && xx >= 0 && yy < bh && xx < bw) {
                        nbE += raw[static_cast<size_t>(yy) * bw + xx].e90;
                        nbN += std::log1p(raw[static_cast<size_t>(yy) * bw + xx].n);
                        nb++;
                    }
                }
            nbE /= std::max(nb, 1);
            nbN /= std::max(nb, 1);
            BlockFeatures b;
            b.x = bx * bs;
            b.y = by * bs;
            b.size = bs;
            double ln = std::log1p(r.n);
            b.f = {lr(r.e90, mE90), lr(r.e70, mE70), static_cast<float>(ln - mN), lr(r.g, mG),
                   static_cast<float>((r.e90 - mE90) / dE90), static_cast<float>((ln - mN) / dN), lr(r.grid, mGrid),
                   static_cast<float>(r.sat - mSat), lr(r.e90 / (std::sqrt(r.n) + 1), mE90 / (std::exp(mN / 2) + 1)),
                   static_cast<float>(r.e90), static_cast<float>(ln), static_cast<float>(r.lum / 255.0),
                   lr(r.e90, nbE), static_cast<float>(ln - nbN)};
            size_t k = static_cast<size_t>(by) * bw + bx;
            b.f.push_back(lr(rq0[k], mQ0));
            b.f.push_back(static_cast<float>((rq0[k] - mQ0) / dQ0));
            b.f.push_back(lr(rq4[k], mQ4));
            b.f.push_back(static_cast<float>(rhf[k] - mHf));
            out.push_back(std::move(b));
        }
    return out;
}

// ================================================================ AUDIO ==
static uint32_t le32(const std::string& b, size_t o) {
    return o + 4 <= b.size() ? (uint8_t)b[o] | ((uint8_t)b[o + 1] << 8) | ((uint8_t)b[o + 2] << 16) | ((uint32_t)(uint8_t)b[o + 3] << 24) : 0;
}
static uint16_t le16(const std::string& b, size_t o) {
    return o + 2 <= b.size() ? static_cast<uint16_t>((uint8_t)b[o] | ((uint8_t)b[o + 1] << 8)) : 0;
}

bool decodeWav(const std::string& b, std::vector<float>& mono, int& sampleRate) {
    if (b.size() < 44 || b.compare(0, 4, "RIFF") != 0 || b.compare(8, 4, "WAVE") != 0) return false;
    uint16_t fmt = 1, ch = 1, bits = 16;
    uint32_t sr = 16000;
    size_t dataOff = 0, dataLen = 0, pos = 12;
    while (pos + 8 <= b.size()) {
        std::string id = b.substr(pos, 4);
        uint32_t len = le32(b, pos + 4);
        if (id == "fmt ") { fmt = le16(b, pos + 8); ch = le16(b, pos + 10); sr = le32(b, pos + 12); bits = le16(b, pos + 22); }
        else if (id == "data") { dataOff = pos + 8; dataLen = std::min<size_t>(len, b.size() - dataOff); break; }
        pos += 8 + len + (len & 1);
    }
    if (!dataOff || ch == 0) return false;
    size_t bytesPer = bits / 8;
    if (bytesPer == 0) return false;
    size_t frames = dataLen / (bytesPer * ch);
    mono.assign(frames, 0);
    for (size_t f = 0; f < frames; ++f) {
        double s = 0;
        for (uint16_t c = 0; c < ch; ++c) {
            size_t o = dataOff + (f * ch + c) * bytesPer;
            double v = 0;
            if (fmt == 3 && bits == 32) { uint32_t u = le32(b, o); float fl; std::memcpy(&fl, &u, 4); v = fl; }
            else if (bits == 16) v = static_cast<int16_t>(le16(b, o)) / 32768.0;
            else if (bits == 8) v = (static_cast<uint8_t>(b[o]) - 128) / 128.0;
            else if (bits == 24) { int32_t x = (uint8_t)b[o] | ((uint8_t)b[o + 1] << 8) | ((int8_t)b[o + 2] << 16); v = x / 8388608.0; }
            else if (bits == 32) v = static_cast<int32_t>(le32(b, o)) / 2147483648.0;
            s += v;
        }
        mono[f] = static_cast<float>(s / ch);
    }
    sampleRate = static_cast<int>(sr);
    return true;
}

std::string encodeWav16(const std::vector<float>& x, int sr) {
    std::string o;
    auto w32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) o.push_back(static_cast<char>((v >> (8 * i)) & 255)); };
    auto w16 = [&](uint16_t v) { o.push_back(static_cast<char>(v & 255)); o.push_back(static_cast<char>(v >> 8)); };
    o += "RIFF"; w32(36 + static_cast<uint32_t>(x.size()) * 2); o += "WAVEfmt "; w32(16); w16(1); w16(1); w32(sr); w32(sr * 2); w16(2); w16(16);
    o += "data"; w32(static_cast<uint32_t>(x.size()) * 2);
    for (float v : x) w16(static_cast<uint16_t>(static_cast<int16_t>(std::clamp(v, -1.0f, 1.0f) * 32767)));
    return o;
}

std::vector<float> resampleLinear(const std::vector<float>& in, int from, int to) {
    if (from == to || in.empty()) return in;
    size_t n = static_cast<size_t>(static_cast<double>(in.size()) * to / from);
    std::vector<float> out(n);
    for (size_t i = 0; i < n; ++i) {
        double src = static_cast<double>(i) * from / to;
        size_t j = static_cast<size_t>(src);
        double f = src - j;
        float a = in[std::min(j, in.size() - 1)], b = in[std::min(j + 1, in.size() - 1)];
        out[i] = static_cast<float>(a * (1 - f) + b * f);
    }
    return out;
}

std::vector<std::vector<std::complex<double>>> stft(const std::vector<float>& x, int nfft, int hop) {
    std::vector<std::vector<std::complex<double>>> S;
    std::vector<double> win(nfft);
    for (int i = 0; i < nfft; ++i) win[i] = 0.5 - 0.5 * std::cos(2 * PI * i / nfft);
    for (size_t start = 0; start + nfft <= x.size(); start += hop) {
        std::vector<std::complex<double>> fr(nfft);
        for (int i = 0; i < nfft; ++i) fr[i] = x[start + i] * win[i];
        fft(fr, false);
        S.push_back(std::move(fr));
    }
    return S;
}

std::vector<float> istft(const std::vector<std::vector<std::complex<double>>>& S, int nfft, int hop, size_t length) {
    std::vector<double> out(length, 0), norm(length, 0), win(nfft);
    for (int i = 0; i < nfft; ++i) win[i] = 0.5 - 0.5 * std::cos(2 * PI * i / nfft);
    for (size_t f = 0; f < S.size(); ++f) {
        auto fr = S[f];
        fft(fr, true);
        size_t start = f * hop;
        for (int i = 0; i < nfft && start + i < length; ++i) {
            out[start + i] += fr[i].real() * win[i];
            norm[start + i] += win[i] * win[i];
        }
    }
    std::vector<float> y(length);
    for (size_t i = 0; i < length; ++i) y[i] = static_cast<float>(norm[i] > 1e-8 ? out[i] / norm[i] : 0);
    return y;
}

const std::vector<std::string>& audioFeatureNames() {
    static std::vector<std::string> n = [] {
        std::vector<std::string> v;
        for (int i = 0; i < 13; ++i) v.push_back("mfcc" + std::to_string(i) + "_mean");
        for (int i = 0; i < 13; ++i) v.push_back("mfcc" + std::to_string(i) + "_std");
        for (auto s : {"delta_mfcc_std", "spectral_centroid_mean", "spectral_centroid_std", "spectral_rolloff_mean",
                       "spectral_flatness_mean", "spectral_flatness_std", "zcr_mean", "zcr_std", "rms_cv",
                       "silence_ratio", "clipping_ratio", "hf_energy_ratio", "lf_energy_ratio", "spectral_flux_mean",
                       "spectral_flux_std"})
            v.push_back(s);
        return v;
    }();
    return n;
}

std::vector<float> audioFeatures(const std::vector<float>& x) {
    const int sr = 16000, nfft = 512, win = 400, hop = 160, nMel = 26, nMfcc = 13;
    std::vector<float> zero(audioFeatureNames().size(), 0.0f);
    if (x.size() < static_cast<size_t>(win * 4)) return zero;

    // Mel filterbank
    auto hz2mel = [](double f) { return 2595 * std::log10(1 + f / 700); };
    auto mel2hz = [](double m) { return 700 * (std::pow(10, m / 2595) - 1); };
    std::vector<double> melPts(nMel + 2);
    for (int i = 0; i < nMel + 2; ++i) melPts[i] = mel2hz(hz2mel(20) + (hz2mel(sr / 2.0) - hz2mel(20)) * i / (nMel + 1));
    std::vector<int> bins(nMel + 2);
    for (int i = 0; i < nMel + 2; ++i) bins[i] = static_cast<int>(std::floor((nfft + 1) * melPts[i] / sr));

    std::vector<double> hann(win);
    for (int i = 0; i < win; ++i) hann[i] = 0.5 - 0.5 * std::cos(2 * PI * i / (win - 1));

    std::vector<std::vector<double>> mfccs;
    std::vector<double> centroid, rolloff, flatness, zcr, rms, flux;
    std::vector<double> prevMag;
    double hf = 0, lf = 0, tot = 0;
    long clipped = 0;
    for (float v : x) if (std::fabs(v) > 0.99f) clipped++;
    for (size_t start = 0; start + win <= x.size(); start += hop) {
        std::vector<std::complex<double>> fr(nfft, 0);
        double e = 0;
        int zc = 0;
        for (int i = 0; i < win; ++i) {
            fr[i] = x[start + i] * hann[i];
            e += x[start + i] * x[start + i];
            if (i && ((x[start + i] >= 0) != (x[start + i - 1] >= 0))) zc++;
        }
        fft(fr, false);
        std::vector<double> mag(nfft / 2 + 1), pw(nfft / 2 + 1);
        double sumP = 0, sumFP = 0, logSum = 0;
        for (int k = 0; k <= nfft / 2; ++k) {
            mag[k] = std::abs(fr[k]);
            pw[k] = mag[k] * mag[k] / nfft;
            double f = static_cast<double>(k) * sr / nfft;
            sumP += pw[k];
            sumFP += f * pw[k];
            logSum += std::log(pw[k] + 1e-12);
            if (f > 4000) hf += pw[k];
            if (f < 300) lf += pw[k];
            tot += pw[k];
        }
        double r = std::sqrt(e / win);
        rms.push_back(r);
        zcr.push_back(static_cast<double>(zc) / win);
        if (r < 0.01) continue;  // skip silent frames for spectral stats
        centroid.push_back(sumP > 0 ? sumFP / sumP : 0);
        double cum = 0;
        int ro = 0;
        for (int k = 0; k <= nfft / 2; ++k) { cum += pw[k]; if (cum >= 0.85 * sumP) { ro = k; break; } }
        rolloff.push_back(static_cast<double>(ro) * sr / nfft);
        double am = sumP / (nfft / 2 + 1);
        flatness.push_back(am > 0 ? std::exp(logSum / (nfft / 2 + 1)) / am : 0);
        if (!prevMag.empty()) {
            double fl = 0;
            for (size_t k = 0; k < mag.size(); ++k) { double d = mag[k] - prevMag[k]; fl += d * d; }
            flux.push_back(std::sqrt(fl));
        }
        prevMag = mag;
        std::vector<double> melE(nMel, 0);
        for (int m = 1; m <= nMel; ++m) {
            for (int k = bins[m - 1]; k < bins[m]; ++k)
                if (k >= 0 && k <= nfft / 2 && bins[m] > bins[m - 1]) melE[m - 1] += pw[k] * (k - bins[m - 1]) / static_cast<double>(bins[m] - bins[m - 1]);
            for (int k = bins[m]; k < bins[m + 1]; ++k)
                if (k >= 0 && k <= nfft / 2 && bins[m + 1] > bins[m]) melE[m - 1] += pw[k] * (bins[m + 1] - k) / static_cast<double>(bins[m + 1] - bins[m]);
        }
        std::vector<double> c(nMfcc, 0);
        for (int i = 0; i < nMfcc; ++i)
            for (int m = 0; m < nMel; ++m) c[i] += std::log(melE[m] + 1e-10) * std::cos(PI * i * (m + 0.5) / nMel);
        mfccs.push_back(c);
    }
    if (mfccs.size() < 3) return zero;
    auto meanStd = [](const std::vector<double>& v, double& m, double& s) {
        m = v.empty() ? 0 : std::accumulate(v.begin(), v.end(), 0.0) / v.size();
        double q = 0;
        for (double a : v) q += (a - m) * (a - m);
        s = v.empty() ? 0 : std::sqrt(q / v.size());
    };
    std::vector<float> f;
    std::vector<double> means(nMfcc), stds(nMfcc);
    for (int i = 0; i < nMfcc; ++i) {
        std::vector<double> col;
        for (auto& c : mfccs) col.push_back(c[i]);
        meanStd(col, means[i], stds[i]);
    }
    for (double m : means) f.push_back(static_cast<float>(m));
    for (double s : stds) f.push_back(static_cast<float>(s));
    double dsum = 0;
    for (size_t t = 1; t < mfccs.size(); ++t)
        for (int i = 1; i < nMfcc; ++i) dsum += std::fabs(mfccs[t][i] - mfccs[t - 1][i]);
    f.push_back(static_cast<float>(dsum / ((mfccs.size() - 1) * (nMfcc - 1))));
    double m, s;
    meanStd(centroid, m, s); f.push_back(static_cast<float>(m / 1000)); f.push_back(static_cast<float>(s / 1000));
    meanStd(rolloff, m, s); f.push_back(static_cast<float>(m / 1000));
    meanStd(flatness, m, s); f.push_back(static_cast<float>(m)); f.push_back(static_cast<float>(s));
    meanStd(zcr, m, s); f.push_back(static_cast<float>(m)); f.push_back(static_cast<float>(s));
    meanStd(rms, m, s); f.push_back(static_cast<float>(m > 0 ? s / m : 0));
    long silent = std::count_if(rms.begin(), rms.end(), [](double r) { return r < 0.01; });
    f.push_back(static_cast<float>(static_cast<double>(silent) / rms.size()));
    f.push_back(static_cast<float>(static_cast<double>(clipped) / x.size()));
    f.push_back(static_cast<float>(tot > 0 ? hf / tot : 0));
    f.push_back(static_cast<float>(tot > 0 ? lf / tot : 0));
    meanStd(flux, m, s); f.push_back(static_cast<float>(m)); f.push_back(static_cast<float>(s));
    return f;
}

}  // namespace cyberguard::features
