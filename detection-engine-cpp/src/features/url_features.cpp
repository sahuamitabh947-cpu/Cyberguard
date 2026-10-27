#include "url_features.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <unordered_set>

#include "../brands.h"
#include "../url_parser.h"

namespace cyberguard::features {

const std::vector<std::string>& urlFeatureNames() {
    static const std::vector<std::string> names = {
        "url_length", "host_length", "path_length", "query_length", "host_dots", "host_hyphens",
        "host_digits", "subdomain_levels", "host_entropy", "url_entropy", "digit_ratio",
        "special_char_ratio", "is_ip_host", "has_userinfo_at", "path_double_slash", "num_query_params",
        "num_percent_encoded", "nonstandard_port", "suspicious_tld", "tld_length", "path_depth",
        "suspicious_word_count", "brand_not_on_official_domain", "min_brand_edit_distance",
        "is_url_shortener", "idn_or_punycode", "longest_token", "avg_token_length",
        "executable_extension", "redirect_parameter", "max_consonant_run", "vowel_ratio",
        "domain_label_length", "path_contains_domain", "num_ampersand", "num_equals",
        "long_hex_sequence", "digit_letter_switches", "script_extension", "num_underscores",
        "num_tilde", "subdomain_length"};
    return names;
}

int levenshtein(const std::string& a, const std::string& b, int cap) {
    if (std::abs(static_cast<int>(a.size()) - static_cast<int>(b.size())) > cap) return cap;
    std::vector<int> prev(b.size() + 1), cur(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) prev[j] = static_cast<int>(j);
    for (size_t i = 1; i <= a.size(); ++i) {
        cur[0] = static_cast<int>(i);
        for (size_t j = 1; j <= b.size(); ++j)
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)});
        std::swap(prev, cur);
    }
    return std::min(prev[b.size()], cap);
}

static std::string stripSchemeAndWww(const std::string& url) {
    std::string s = url;
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    size_t p = s.find("://");
    if (p != std::string::npos && p < 12) s = s.substr(p + 3);
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.rfind("www.", 0) == 0) s = s.substr(4);
    while (!s.empty() && (s.back() == '/' || std::isspace(static_cast<unsigned char>(s.back())))) s.pop_back();
    return s;
}

std::string canonicalUrlForModel(const std::string& url) {
    std::string s = stripSchemeAndWww(url);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

std::vector<float> urlFeatures(const std::string& rawUrl) {
    static const std::unordered_set<std::string> suspiciousTlds = {
        "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click", "loan", "icu", "buzz",
        "rest", "fit", "country", "kim", "cam", "support", "live", "online", "site", "shop", "cyou", "cfd", "sbs"};
    static const std::unordered_set<std::string> shorteners = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
        "tiny.cc", "rebrand.ly", "t.ly", "s.id", "bitly.com", "lnkd.in", "trib.al", "v.gd", "qr.ae"};
    static const std::vector<std::string> words = {
        "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
        "banking", "confirm", "password", "webscr", "cmd=", "ebayisapi", "wallet", "unlock", "suspend",
        "reset", "billing", "payment", "invoice", "free", "bonus", "lucky", "prize", "kyc", "otp", "refund"};

    std::string canon = canonicalUrlForModel(rawUrl);
    ParsedUrl u = parseUrl("http://" + stripSchemeAndWww(rawUrl));
    std::string host = u.host;
    if (host.rfind("www.", 0) == 0) host = host.substr(4);
    std::string pathQ = u.path + (u.query.empty() ? "" : "?" + u.query);
    std::string lowerPath = pathQ;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    auto count = [](const std::string& s, char c) { return static_cast<float>(std::count(s.begin(), s.end(), c)); };
    float digits = 0, letters = 0, special = 0;
    for (unsigned char c : canon) {
        if (std::isdigit(c)) digits++;
        else if (std::isalpha(c)) letters++;
        else special++;
    }
    float len = std::max<float>(1.0f, static_cast<float>(canon.size()));

    // tokens
    std::vector<std::string> tokens;
    std::string cur;
    for (unsigned char c : canon) {
        if (std::isalnum(c)) cur.push_back(static_cast<char>(c));
        else { if (!cur.empty()) tokens.push_back(cur); cur.clear(); }
    }
    if (!cur.empty()) tokens.push_back(cur);
    float longest = 0, sumTok = 0;
    for (auto& t : tokens) { longest = std::max<float>(longest, static_cast<float>(t.size())); sumTok += static_cast<float>(t.size()); }

    std::string tld = u.publicSuffix.empty() ? "" : u.publicSuffix.substr(u.publicSuffix.rfind('.') == std::string::npos ? 0 : u.publicSuffix.rfind('.') + 1);
    std::string label = u.domainLabel;
    std::string sub = u.subdomain;
    if (sub.rfind("www", 0) == 0) sub = sub.size() > 4 ? sub.substr(4) : "";

    float subLevels = sub.empty() ? 0 : count(sub, '.') + 1;
    float suspiciousWords = 0;
    std::string lowerAll = canon;
    for (auto& w : words)
        if (lowerAll.find(w) != std::string::npos) suspiciousWords++;

    // Brand checks against the homograph skeleton of the host.
    bool official = isOfficialBrandDomain(u.registrableDomain);
    float brandMismatch = 0, minBrandDist = 10;
    std::string skelLabel = homographSkeleton(label);
    for (auto& b : knownBrands()) {
        if (b.name.size() < 4) {
            // short names (sbi, dhl) only count as exact label/subdomain tokens
            if (!official && (skelLabel == b.name || sub.find(b.name + ".") != std::string::npos ||
                              sub == b.name || lowerPath.find("/" + b.name) != std::string::npos))
                brandMismatch = 1;
        } else if (!official && (host.find(b.name) != std::string::npos || homographSkeleton(host).find(b.name) != std::string::npos ||
                                 lowerPath.find(b.name) != std::string::npos))
            brandMismatch = 1;
        if (!official && !skelLabel.empty())
            minBrandDist = std::min<float>(minBrandDist, static_cast<float>(levenshtein(skelLabel, b.name, 10)));
    }
    if (official) minBrandDist = 10;

    int maxCons = 0, consRun = 0, vowels = 0, alphaInLabel = 0, switches = 0;
    int prevType = -1;
    for (unsigned char c : label) {
        bool isV = std::string("aeiou").find(static_cast<char>(c)) != std::string::npos;
        if (std::isalpha(c)) {
            alphaInLabel++;
            if (isV) { vowels++; consRun = 0; }
            else { consRun++; maxCons = std::max(maxCons, consRun); }
        } else consRun = 0;
        int type = std::isdigit(c) ? 1 : (std::isalpha(c) ? 0 : 2);
        if (prevType >= 0 && type != prevType && type < 2 && prevType < 2) switches++;
        prevType = type;
    }

    int hexRun = 0, maxHexRun = 0;
    for (unsigned char c : canon) {
        if (std::isxdigit(c)) { hexRun++; maxHexRun = std::max(maxHexRun, hexRun); } else hexRun = 0;
    }

    auto endsWith = [](const std::string& s, const std::string& e) {
        return s.size() >= e.size() && s.compare(s.size() - e.size(), e.size(), e) == 0;
    };
    std::string lowerPathOnly = u.path;
    std::transform(lowerPathOnly.begin(), lowerPathOnly.end(), lowerPathOnly.begin(), ::tolower);
    bool exec = false, script = false;
    for (auto e : {".exe", ".apk", ".scr", ".msi", ".bat", ".jar", ".vbs", ".dll", ".bin", ".sh", ".zip", ".rar", ".7z", ".iso"})
        if (endsWith(lowerPathOnly, e)) exec = true;
    for (auto e : {".php", ".asp", ".aspx", ".cgi", ".jsp", ".html", ".htm"})
        if (endsWith(lowerPathOnly, e)) script = true;

    bool redirectParam = false;
    for (auto& k : u.queryKeys)
        for (auto r : {"url", "redirect", "redirect_uri", "redir", "next", "return", "returnurl", "goto", "dest", "destination", "continue", "target", "r", "u"})
            if (k == r) redirectParam = true;
    if (lowerPath.find("http%3a") != std::string::npos || lowerPath.find("=http") != std::string::npos) redirectParam = true;

    bool pathDomain = false;
    for (auto t : {".com", ".net", ".org", ".in/", "www.", ".co.", ".gov"})
        if (lowerPath.find(t) != std::string::npos) pathDomain = true;

    bool nonStdPort = !u.port.empty() && u.port != "80" && u.port != "443";
    float depth = 0;
    for (char c : u.path) if (c == '/') depth++;

    std::vector<float> f = {
        static_cast<float>(canon.size()), static_cast<float>(host.size()), static_cast<float>(u.path.size()),
        static_cast<float>(u.query.size()), count(host, '.'), count(host, '-'),
        static_cast<float>(std::count_if(host.begin(), host.end(), [](unsigned char c) { return std::isdigit(c); })),
        subLevels, static_cast<float>(shannonEntropy(host)), static_cast<float>(shannonEntropy(canon)),
        digits / len, special / len, (u.isIPv4 || u.isIPv6) ? 1.0f : 0.0f, u.userinfo.empty() ? 0.0f : 1.0f,
        u.path.find("//") != std::string::npos ? 1.0f : 0.0f, static_cast<float>(u.queryKeys.size()),
        count(canon, '%'), nonStdPort ? 1.0f : 0.0f, suspiciousTlds.count(tld) ? 1.0f : 0.0f,
        static_cast<float>(tld.size()), depth, suspiciousWords, brandMismatch, minBrandDist,
        (shorteners.count(host) || shorteners.count(u.registrableDomain)) ? 1.0f : 0.0f,
        (u.hasPunycode || u.nonAsciiHost) ? 1.0f : 0.0f, longest, tokens.empty() ? 0.0f : sumTok / tokens.size(),
        exec ? 1.0f : 0.0f, redirectParam ? 1.0f : 0.0f, static_cast<float>(maxCons),
        alphaInLabel ? static_cast<float>(vowels) / alphaInLabel : 0.0f, static_cast<float>(label.size()),
        pathDomain ? 1.0f : 0.0f, count(canon, '&'), count(canon, '='), maxHexRun >= 16 ? 1.0f : 0.0f,
        static_cast<float>(switches), script ? 1.0f : 0.0f, count(canon, '_'), count(canon, '~'),
        static_cast<float>(sub.size())};
    return f;
}

}  // namespace cyberguard::features
