#pragma once
// Brands commonly impersonated in phishing (global + India), with their
// official registrable domains. Used by the URL analyzer, URL ML features
// and the email sender checks.
#include <string>
#include <vector>

namespace cyberguard {

struct Brand {
    std::string name;                        // keyword looked for in hosts/paths/text
    std::vector<std::string> officialDomains; // registrable domains that are genuinely theirs
};

inline const std::vector<Brand>& knownBrands() {
    static const std::vector<Brand> brands = {
        {"paypal", {"paypal.com", "paypal.me", "paypalobjects.com"}},
        {"google", {"google.com", "google.co.in", "gmail.com", "googleusercontent.com", "gstatic.com", "youtube.com", "googleapis.com", "goo.gl", "g.co"}},
        {"gmail", {"gmail.com", "google.com"}},
        {"microsoft", {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com", "windows.net", "azure.com", "msn.com"}},
        {"outlook", {"outlook.com", "live.com", "office.com", "microsoft.com"}},
        {"office365", {"office.com", "office365.com", "microsoft.com", "microsoftonline.com"}},
        {"apple", {"apple.com", "icloud.com", "apple.co"}},
        {"icloud", {"icloud.com", "apple.com"}},
        {"amazon", {"amazon.com", "amazon.in", "amazonaws.com", "amazon.co.uk", "amzn.to", "media-amazon.com"}},
        {"netflix", {"netflix.com", "nflxext.com"}},
        {"facebook", {"facebook.com", "fb.com", "fbcdn.net", "meta.com"}},
        {"instagram", {"instagram.com", "cdninstagram.com"}},
        {"whatsapp", {"whatsapp.com", "whatsapp.net", "wa.me"}},
        {"linkedin", {"linkedin.com", "licdn.com", "lnkd.in"}},
        {"github", {"github.com", "githubusercontent.com", "github.io"}},
        {"dropbox", {"dropbox.com", "dropboxusercontent.com"}},
        {"adobe", {"adobe.com", "adobelogin.com"}},
        {"yahoo", {"yahoo.com", "yahoo.co.in"}},
        {"twitter", {"twitter.com", "x.com", "t.co"}},
        {"docusign", {"docusign.com", "docusign.net"}},
        {"dhl", {"dhl.com", "dhl.co.in"}},
        {"fedex", {"fedex.com"}},
        {"sbi", {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"}},
        {"onlinesbi", {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"}},
        {"hdfc", {"hdfcbank.com", "hdfc.com", "hdfcbank.bank.in"}},
        {"icici", {"icicibank.com", "icici.bank.in"}},
        {"axisbank", {"axisbank.com", "axis.bank.in"}},
        {"kotak", {"kotak.com", "kotak.bank.in"}},
        {"irctc", {"irctc.co.in", "irctc.com"}},
        {"incometax", {"incometax.gov.in", "incometaxindia.gov.in"}},
        {"uidai", {"uidai.gov.in"}},
        {"aadhaar", {"uidai.gov.in"}},
        {"paytm", {"paytm.com", "paytm.in"}},
        {"phonepe", {"phonepe.com"}},
        {"flipkart", {"flipkart.com"}},
        {"npci", {"npci.org.in"}},
        {"epfo", {"epfindia.gov.in"}},
        {"steam", {"steampowered.com", "steamcommunity.com"}},
        {"binance", {"binance.com"}},
        {"coinbase", {"coinbase.com"}},
        {"metamask", {"metamask.io"}},
    };
    return brands;
}

inline bool isOfficialBrandDomain(const std::string& registrable) {
    for (auto& b : knownBrands())
        for (auto& d : b.officialDomains)
            if (registrable == d) return true;
    return false;
}

}  // namespace cyberguard
