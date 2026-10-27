#pragma once
// Image and audio feature extraction for the deepfake / manipulation models.
#include <complex>
#include <cstdint>
#include <string>
#include <vector>

namespace cyberguard::features {

// ------------------------------------------------------------------ FFT --
void fft(std::vector<std::complex<double>>& a, bool inverse);  // size must be power of two

// ---------------------------------------------------------------- Image --
struct RgbImage {
    int w = 0, h = 0;
    std::vector<uint8_t> px;  // RGB, row-major
};

bool decodeImage(const std::string& bytes, RgbImage& out);
std::string encodeJpeg(const RgbImage& img, int quality);
RgbImage cropCenter(const RgbImage& img, int maxSide);
RgbImage cropAt(const RgbImage& img, int x, int y, int w, int h);
RgbImage resizeBilinear(const RgbImage& img, int w, int h);

const std::vector<std::string>& imageFeatureNames();
// Forensic features: error-level analysis, noise-residual consistency,
// JPEG blockiness, frequency spectrum shape, colour-residual correlation.
std::vector<float> imageFeatures(const RgbImage& img);

// Block-level (32x32) features, each expressed RELATIVE to the image's own
// median statistics, so a region whose compression/noise traces differ from
// the rest of the picture stands out (splicing, copy-move, retouching).
struct BlockFeatures {
    int x = 0, y = 0, size = 32;
    std::vector<float> f;
};
const std::vector<std::string>& imageBlockFeatureNames();
std::vector<BlockFeatures> imageBlockFeatures(const RgbImage& img);

// ---------------------------------------------------------------- Audio --
bool decodeWav(const std::string& bytes, std::vector<float>& mono, int& sampleRate);
std::string encodeWav16(const std::vector<float>& mono, int sampleRate);
std::vector<float> resampleLinear(const std::vector<float>& in, int from, int to);

const std::vector<std::string>& audioFeatureNames();
// Expects mono samples at 16 kHz in [-1, 1].
std::vector<float> audioFeatures(const std::vector<float>& samples16k);

// STFT helpers (Hann window) used for Griffin-Lim resynthesis in training.
std::vector<std::vector<std::complex<double>>> stft(const std::vector<float>& x, int nfft, int hop);
std::vector<float> istft(const std::vector<std::vector<std::complex<double>>>& S, int nfft, int hop, size_t length);

}  // namespace cyberguard::features
