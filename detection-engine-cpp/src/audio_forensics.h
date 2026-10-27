#pragma once
#include <string>
#include "json.hpp"

using json = nlohmann::json;

namespace cyberguard {

// Extracts low-level signal-processing features from a raw WAV audio buffer:
// clipping ratio, silence ratio, and spectral flatness (via a direct DFT on
// a downsampled window). These are genuine, computed DSP features -- not a
// trained voice-clone classifier. Synthetic/TTS voice clips frequently show
// unnaturally low silence variance and abnormally flat or abnormally peaked
// spectra compared to natural speech, so these features are combined with
// Gemini's audio understanding (which reasons over the actual audio content)
// for the final verdict, exactly as with the image forensics module.
class AudioForensics {
public:
    json analyze(const std::string& base64OrRawBytes, bool isBase64) const;

private:
    std::string decodeBase64(const std::string& in) const;
};

} // namespace cyberguard
