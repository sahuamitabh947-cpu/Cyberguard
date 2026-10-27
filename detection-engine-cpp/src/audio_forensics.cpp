#include "audio_forensics.h"
#include <vector>
#include <cstdint>
#include <cmath>
#include <cstring>

namespace cyberguard {

std::string AudioForensics::decodeBase64(const std::string& in) const {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)chars[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back(char((val >> valb) & 0xFF)); valb -= 8; }
    }
    return out;
}

static uint32_t readLE32(const std::string& b, size_t off) {
    if (off + 4 > b.size()) return 0;
    return (uint8_t)b[off] | ((uint8_t)b[off+1] << 8) | ((uint8_t)b[off+2] << 16) | ((uint8_t)b[off+3] << 24);
}
static uint16_t readLE16(const std::string& b, size_t off) {
    if (off + 2 > b.size()) return 0;
    return (uint8_t)b[off] | ((uint8_t)b[off+1] << 8);
}

json AudioForensics::analyze(const std::string& input, bool isBase64) const {
    std::string bytes = isBase64 ? decodeBase64(input) : input;
    struct Finding { std::string indicator; std::string detail; int weight; };
    std::vector<Finding> findings;
    int score = 0;

    bool isWav = bytes.size() > 12 && bytes.substr(0, 4) == "RIFF" && bytes.substr(8, 4) == "WAVE";
    if (!isWav) {
        return json{
            {"score", 0}, {"riskLevel", "Safe"}, {"findings", json::array()},
            {"format", "non-wav"},
            {"note", "Local signal-level forensics only run on WAV audio; combine with Gemini audio understanding for other formats (mp3/m4a/ogg)."}
        };
    }

    // Walk RIFF chunks to find "fmt " and "data"
    uint16_t numChannels = 1, bitsPerSample = 16;
    uint32_t sampleRate = 44100;
    size_t dataOffset = 0, dataSize = 0;
    size_t pos = 12;
    while (pos + 8 <= bytes.size()) {
        std::string chunkId = bytes.substr(pos, 4);
        uint32_t chunkSize = readLE32(bytes, pos + 4);
        if (chunkId == "fmt ") {
            numChannels = readLE16(bytes, pos + 10);
            sampleRate = readLE32(bytes, pos + 12);
            bitsPerSample = readLE16(bytes, pos + 22);
        } else if (chunkId == "data") {
            dataOffset = pos + 8;
            dataSize = chunkSize;
        }
        pos += 8 + chunkSize + (chunkSize % 2); // chunks are word-aligned
        if (chunkId == "data") break;
    }

    if (dataOffset == 0 || bitsPerSample != 16 || dataSize < 4) {
        return json{
            {"score", 0}, {"riskLevel", "Safe"}, {"findings", json::array()},
            {"format", "wav"},
            {"note", "Only 16-bit PCM WAV is analyzed locally; file format/bit depth not supported for signal analysis. Combine with Gemini audio understanding."}
        };
    }

    size_t numSamples = std::min(dataSize, bytes.size() - dataOffset) / 2;
    std::vector<int16_t> samples(numSamples);
    for (size_t i = 0; i < numSamples; i++) {
        size_t off = dataOffset + i * 2;
        samples[i] = (int16_t)((uint8_t)bytes[off] | ((uint8_t)bytes[off+1] << 8));
    }

    // --- Clipping ratio ---
    size_t clipped = 0;
    for (auto s : samples) if (std::abs((int)s) >= 32000) clipped++;
    double clippingRatio = numSamples > 0 ? (double)clipped / numSamples : 0.0;

    // --- Silence ratio ---
    size_t silent = 0;
    for (auto s : samples) if (std::abs((int)s) < 200) silent++;
    double silenceRatio = numSamples > 0 ? (double)silent / numSamples : 0.0;

    // --- Spectral flatness on a representative window (direct DFT, small N) ---
    const size_t N = std::min<size_t>(2048, numSamples);
    double geoMeanLog = 0.0, arithMean = 0.0;
    if (N >= 64) {
        std::vector<double> mag(N / 2);
        size_t start = numSamples / 2 - N / 2; // sample from the middle of the clip
        for (size_t k = 0; k < N / 2; k++) {
            double re = 0.0, im = 0.0;
            for (size_t n = 0; n < N; n++) {
                double angle = -2.0 * M_PI * k * n / (double)N;
                double sampleVal = samples[start + n] / 32768.0;
                re += sampleVal * std::cos(angle);
                im += sampleVal * std::sin(angle);
            }
            mag[k] = std::sqrt(re * re + im * im) + 1e-9;
        }
        for (double m : mag) { geoMeanLog += std::log(m); arithMean += m; }
        geoMeanLog /= mag.size();
        arithMean /= mag.size();
    }
    double spectralFlatness = arithMean > 0 ? std::exp(geoMeanLog) / arithMean : 0.0; // 0 (tonal) .. 1 (flat/noise-like)

    if (clippingRatio > 0.02) {
        findings.push_back({ "audio_clipping", "Elevated sample clipping ratio (" + std::to_string((int)(clippingRatio*100)) + "%), consistent with over-driven synthetic playback or re-recording", 15 });
        score += 15;
    }
    if (silenceRatio > 0.6) {
        findings.push_back({ "excessive_silence", "Unusually high proportion of near-silent samples, atypical for natural conversational speech", 10 });
        score += 10;
    }
    if (spectralFlatness > 0.55) {
        findings.push_back({ "high_spectral_flatness", "Spectral flatness is high (" + std::to_string((int)(spectralFlatness*100)) + "/100), suggesting noise-like or synthetic texture rather than natural voiced speech harmonics", 20 });
        score += 20;
    } else if (spectralFlatness < 0.02 && N >= 64) {
        findings.push_back({ "abnormally_tonal_spectrum", "Spectrum is unusually pure/tonal for speech, which can indicate vocoder-based voice synthesis", 15 });
        score += 15;
    }

    if (score > 100) score = 100;
    std::string riskLevel;
    if (score >= 80) riskLevel = "Critical";
    else if (score >= 55) riskLevel = "High";
    else if (score >= 30) riskLevel = "Medium";
    else if (score >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    json findingsJson = json::array();
    for (const auto& f : findings) findingsJson.push_back({ {"indicator", f.indicator}, {"detail", f.detail}, {"weight", f.weight} });

    return json{
        {"score", score},
        {"riskLevel", riskLevel},
        {"format", "wav"},
        {"sampleRate", sampleRate},
        {"channels", numChannels},
        {"durationSeconds", sampleRate > 0 ? (double)numSamples / numChannels / sampleRate : 0},
        {"findings", findingsJson},
        {"note", "Signal-level forensic layer only; combine with Gemini audio understanding for full voice-clone/deepfake assessment."}
    };
}

} // namespace cyberguard
