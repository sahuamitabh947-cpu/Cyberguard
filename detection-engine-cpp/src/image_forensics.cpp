#include "image_forensics.h"
#include <vector>
#include <cstdint>

namespace cyberguard {

std::string ImageForensics::decodeBase64(const std::string& in) const {
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
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

json ImageForensics::analyze(const std::string& input, bool isBase64) const {
    std::string bytes = isBase64 ? decodeBase64(input) : input;
    struct Finding { std::string indicator; std::string detail; int weight; };
    std::vector<Finding> findings;
    int score = 0;

    if (bytes.size() < 4) {
        return json{ {"score", 0}, {"riskLevel", "Safe"}, {"findings", json::array()}, {"note", "insufficient data"} };
    }

    auto u8 = [&](size_t i) -> uint8_t { return (uint8_t)bytes[i]; };
    bool isJpeg = bytes.size() > 2 && u8(0) == 0xFF && u8(1) == 0xD8;
    bool isPng = bytes.size() > 8 && u8(0) == 0x89 && u8(1) == 0x50 && u8(2) == 0x4E && u8(3) == 0x47;

    if (!isJpeg && !isPng) {
        findings.push_back({ "unrecognised_format", "File does not match standard JPEG/PNG signatures", 15 });
        score += 15;
    }

    if (isJpeg) {
        // Walk JPEG markers, counting APPn segments and quantization tables.
        int appSegments = 0, quantTables = 0, sofSegments = 0;
        bool hasExif = false;
        size_t i = 2;
        while (i + 4 < bytes.size()) {
            if (u8(i) != 0xFF) { i++; continue; }
            uint8_t marker = u8(i + 1);
            if (marker == 0xD8 || marker == 0xD9) { i += 2; continue; }
            if (marker >= 0xD0 && marker <= 0xD7) { i += 2; continue; }
            if (i + 3 >= bytes.size()) break;
            int segLen = (u8(i + 2) << 8) | u8(i + 3);
            if (marker >= 0xE0 && marker <= 0xEF) {
                appSegments++;
                if (marker == 0xE1) hasExif = true;
            }
            if (marker == 0xDB) quantTables++;
            if (marker == 0xC0 || marker == 0xC2) sofSegments++;
            if (marker == 0xDA) break; // start of scan -> stop header parsing
            if (segLen < 2) break;
            i += 2 + segLen;
        }

        if (!hasExif) {
            findings.push_back({ "missing_exif", "No EXIF metadata block found; original camera images typically retain EXIF, while AI-generated or stripped/re-saved images often do not", 15 });
            score += 15;
        }
        if (quantTables >= 2) {
            findings.push_back({ "multiple_quant_tables", "Multiple quantization tables detected, consistent with recompression across more than one encoding pass", 12 });
            score += 12;
        }
        if (appSegments == 0) {
            findings.push_back({ "no_app_segments", "No application metadata segments present at all, unusual for camera or standard editor output", 8 });
            score += 8;
        }
    } else if (isPng) {
        bool hasTextChunk = false;
        size_t i = 8;
        while (i + 8 < bytes.size()) {
            uint32_t len = (u8(i) << 24) | (u8(i+1) << 16) | (u8(i+2) << 8) | u8(i+3);
            std::string type = bytes.substr(i + 4, 4);
            if (type == "tEXt" || type == "iTXt" || type == "zTXt") hasTextChunk = true;
            if (type == "IEND") break;
            i += 8 + len + 4;
            if (len > bytes.size()) break;
        }
        if (!hasTextChunk) {
            findings.push_back({ "no_metadata_chunks", "PNG has no text/metadata chunks (e.g. software tag), which many AI image generators omit or strip", 10 });
            score += 10;
        }
    }

    if (score > 100) score = 100;
    std::string riskLevel;
    if (score >= 80) riskLevel = "Critical";
    else if (score >= 55) riskLevel = "High";
    else if (score >= 30) riskLevel = "Medium";
    else if (score >= 10) riskLevel = "Low";
    else riskLevel = "Safe";

    json findingsJson = json::array();
    for (const auto& f : findings) {
        findingsJson.push_back({ {"indicator", f.indicator}, {"detail", f.detail}, {"weight", f.weight} });
    }

    return json{
        {"score", score},
        {"riskLevel", riskLevel},
        {"format", isJpeg ? "jpeg" : (isPng ? "png" : "unknown")},
        {"findings", findingsJson},
        {"note", "Forensic signal layer only; combine with Gemini multimodal analysis for the full deepfake assessment."}
    };
}

} // namespace cyberguard
