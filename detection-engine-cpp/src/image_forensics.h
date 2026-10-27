#pragma once
#include <string>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Extracts low-level forensic signals from raw image bytes: presence/absence
// of EXIF metadata, multiple JPEG APP/quantization markers (a proxy for
// recompression / re-encoding, common after an image passes through a
// generation or editing pipeline), and basic file-structure anomalies.
//
// IMPORTANT (documented for the README too): this is a fast, dependency-free
// *signal extractor*, not a trained deepfake classifier. It supplies real,
// genuine indicators that feed into the overall risk score alongside the
// Gemini multimodal analysis, which does the actual visual/semantic
// deepfake reasoning. Presenting this alone as "deepfake detection" would
// overstate its accuracy, so it is always combined with the AI layer.
class ImageForensics {
public:
    json analyze(const std::string& base64OrRawBytes, bool isBase64) const;

private:
    std::string decodeBase64(const std::string& in) const;
};

} // namespace cyberguard
