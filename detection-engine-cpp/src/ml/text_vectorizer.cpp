#include "text_vectorizer.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <unordered_set>

namespace cyberguard::ml {

std::vector<std::string> TextVectorizer::wordTokens(const std::string& text) {
    std::vector<std::string> out;
    std::string lower;
    lower.reserve(text.size());
    for (unsigned char c : text) lower.push_back(static_cast<char>(std::tolower(c)));

    size_t i = 0, n = lower.size();
    auto startsWith = [&](size_t pos, const char* s) {
        size_t len = std::char_traits<char>::length(s);
        return lower.compare(pos, len, s) == 0;
    };
    while (i < n) {
        unsigned char c = lower[i];
        if (startsWith(i, "http://") || startsWith(i, "https://") || startsWith(i, "www.")) {
            while (i < n && !std::isspace(static_cast<unsigned char>(lower[i]))) ++i;
            out.emplace_back("__url__");
            continue;
        }
        if (std::isalnum(c) || c == '$' || c == '@' || c >= 0x80) {
            size_t j = i;
            bool hasAt = false, hasDigit = false, hasAlpha = false, hasMoney = false;
            while (j < n) {
                unsigned char d = lower[j];
                if (std::isalnum(d) || d == '@' || d == '.' || d == '_' || d == '$' || d == '\'' || d >= 0x80) {
                    if (d == '@') hasAt = true;
                    if (std::isdigit(d)) hasDigit = true;
                    if (std::isalpha(d) || d >= 0x80) hasAlpha = true;
                    if (d == '$') hasMoney = true;
                    ++j;
                } else break;
            }
            std::string tok = lower.substr(i, j - i);
            while (!tok.empty() && (tok.back() == '.' || tok.back() == '\'')) tok.pop_back();
            i = j;
            if (tok.empty()) continue;
            if (hasAt && tok.find('.') != std::string::npos) out.emplace_back("__email__");
            else if (hasMoney || (tok.size() > 1 && (tok[0] == '$'))) out.emplace_back("__money__");
            else if (hasDigit && !hasAlpha) out.emplace_back(tok.size() >= 7 ? "__longnum__" : "__num__");
            else if (tok.size() >= 2 && tok.size() <= 30) {
                // split on dots inside word tokens (e.g. "paypal.com")
                size_t s = 0;
                for (size_t k = 0; k <= tok.size(); ++k) {
                    if (k == tok.size() || tok[k] == '.' || tok[k] == '_') {
                        if (k > s + 1) out.push_back(tok.substr(s, k - s));
                        s = k + 1;
                    }
                }
            }
            continue;
        }
        if (c == '!') out.emplace_back("__excl__");
        ++i;
    }
    return out;
}

std::vector<std::string> TextVectorizer::terms(const std::string& doc) const {
    std::vector<std::string> t;
    if (params.charMode) {
        std::string s = "^";
        for (unsigned char c : doc) s.push_back(static_cast<char>(std::tolower(c)));
        s.push_back('$');
        for (int k = params.ngramMin; k <= params.ngramMax; ++k)
            for (size_t i = 0; i + k <= s.size(); ++i) t.push_back(s.substr(i, k));
        return t;
    }
    auto words = wordTokens(doc);
    for (int k = params.ngramMin; k <= params.ngramMax; ++k)
        for (size_t i = 0; i + k <= words.size(); ++i) {
            std::string g = words[i];
            for (int m = 1; m < k; ++m) g += " " + words[i + m];
            t.push_back(std::move(g));
        }
    return t;
}

void TextVectorizer::fit(const std::vector<std::string>& docs, const Params& p) {
    params = p;
    std::unordered_map<std::string, int> df;
    for (const auto& d : docs) {
        std::unordered_set<std::string> seen;
        for (auto& t : terms(d)) seen.insert(t);
        for (auto& t : seen) df[t]++;
    }
    std::vector<std::pair<std::string, int>> items;
    for (auto& [t, c] : df)
        if (c >= p.minDf && c < static_cast<int>(docs.size() * 0.95)) items.emplace_back(t, c);
    std::sort(items.begin(), items.end(), [](auto& a, auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    if (items.size() > p.maxFeatures) items.resize(p.maxFeatures);
    std::sort(items.begin(), items.end());  // deterministic index order
    vocab.clear();
    inverse.clear();
    idf.clear();
    double N = static_cast<double>(docs.size());
    for (auto& [t, c] : items) {
        vocab[t] = static_cast<int>(inverse.size());
        inverse.push_back(t);
        idf.push_back(static_cast<float>(std::log((1 + N) / (1 + c)) + 1.0));
    }
}

SparseVec TextVectorizer::counts(const std::string& doc) const {
    std::map<int, float> m;
    for (auto& t : terms(doc)) {
        auto it = vocab.find(t);
        if (it != vocab.end()) m[it->second] += 1.0f;
    }
    return SparseVec(m.begin(), m.end());
}

SparseVec TextVectorizer::transform(const std::string& doc) const {
    SparseVec v = counts(doc);
    double norm = 0;
    for (auto& [j, c] : v) {
        double tf = params.sublinearTf ? 1.0 + std::log(c) : c;
        c = static_cast<float>(tf * idf[j]);
        norm += static_cast<double>(c) * c;
    }
    norm = std::sqrt(norm);
    if (norm > 0)
        for (auto& [j, c] : v) c = static_cast<float>(c / norm);
    return v;
}

json TextVectorizer::toJson() const {
    std::vector<float> idfR(idf.size());
    for (size_t i = 0; i < idf.size(); ++i) idfR[i] = std::round(idf[i] * 1e4f) / 1e4f;
    return json{{"charMode", params.charMode}, {"ngramMin", params.ngramMin}, {"ngramMax", params.ngramMax},
                {"minDf", params.minDf},       {"maxFeatures", params.maxFeatures},
                {"sublinearTf", params.sublinearTf}, {"terms", inverse}, {"idf", idfR}};
}

TextVectorizer TextVectorizer::fromJson(const json& j) {
    TextVectorizer v;
    v.params.charMode = j.at("charMode").get<bool>();
    v.params.ngramMin = j.at("ngramMin").get<int>();
    v.params.ngramMax = j.at("ngramMax").get<int>();
    v.params.minDf = j.at("minDf").get<int>();
    v.params.maxFeatures = j.at("maxFeatures").get<size_t>();
    v.params.sublinearTf = j.at("sublinearTf").get<bool>();
    v.inverse = j.at("terms").get<std::vector<std::string>>();
    v.idf = j.at("idf").get<std::vector<float>>();
    for (size_t i = 0; i < v.inverse.size(); ++i) v.vocab[v.inverse[i]] = static_cast<int>(i);
    return v;
}

}  // namespace cyberguard::ml
