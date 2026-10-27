#pragma once
// TF-IDF vectorizer with a learned vocabulary (so every feature maps back
// to a human-readable token -> used for Explainable-AI output).
// Supports word n-grams (messages/emails) and character n-grams (URLs).
#include <string>
#include <unordered_map>
#include <vector>
#include "ml_core.h"

namespace cyberguard::ml {

class TextVectorizer {
public:
    struct Params {
        bool charMode = false;   // false: word n-grams, true: character n-grams
        int ngramMin = 1, ngramMax = 2;
        int minDf = 3;
        size_t maxFeatures = 40000;
        bool sublinearTf = true;
    };

    void fit(const std::vector<std::string>& docs, const Params& p);
    // L2-normalised TF-IDF vector.
    SparseVec transform(const std::string& doc) const;
    // Raw term counts (for Naive Bayes).
    SparseVec counts(const std::string& doc) const;

    std::vector<std::string> terms(const std::string& doc) const;
    const std::string& termName(int idx) const { return inverse.at(idx); }
    size_t size() const { return inverse.size(); }

    json toJson() const;
    static TextVectorizer fromJson(const json& j);

    // Normalises free text: lowercases and maps URLs/emails/numbers/money to
    // placeholder tokens so the model learns "contains a link" rather than a
    // specific link.
    static std::vector<std::string> wordTokens(const std::string& text);

    Params params;
    std::unordered_map<std::string, int> vocab;
    std::vector<std::string> inverse;
    std::vector<float> idf;
};

}  // namespace cyberguard::ml
