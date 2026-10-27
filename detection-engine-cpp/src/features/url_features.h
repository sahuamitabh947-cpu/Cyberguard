#pragma once
// Lexical URL features for the URL ML models.
// IMPORTANT: features are scheme-invariant by design. The scheme and a
// leading "www." are stripped before extraction, so turning "http://" into
// "https://" cannot change the ML verdict (HTTPS only proves the connection
// is encrypted, not that the site is genuine).
#include <string>
#include <vector>

namespace cyberguard::features {

const std::vector<std::string>& urlFeatureNames();
std::vector<float> urlFeatures(const std::string& url);
// Canonical, scheme-less form fed to the character n-gram model.
std::string canonicalUrlForModel(const std::string& url);
int levenshtein(const std::string& a, const std::string& b, int cap = 64);

}  // namespace cyberguard::features
