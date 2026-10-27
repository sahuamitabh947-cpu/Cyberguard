#include "nids_features.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <unordered_map>

namespace cyberguard::features {

static const std::vector<std::string> kServices = {"http", "http_443", "private", "domain_u", "smtp",
                                                   "ftp_data", "ftp", "ssh", "telnet", "ecr_i",
                                                   "eco_i", "urp_i", "finger", "other"};
static const std::vector<std::string> kFlags = {"SF", "S0", "REJ", "RSTO", "RSTR", "SH",
                                                "S1", "S2", "S3", "OTH", "RSTOS0"};

const std::vector<std::string>& nidsClasses() {
    static const std::vector<std::string> c = {"normal", "dos", "probe", "r2l", "u2r"};
    return c;
}

const std::vector<std::string>& nidsFeatureNames() {
    static std::vector<std::string> names = [] {
        std::vector<std::string> n = {"duration_log", "proto_tcp", "proto_udp", "proto_icmp"};
        for (auto& s : kServices) n.push_back("service_" + s);
        for (auto& f : kFlags) n.push_back("flag_" + f);
        for (auto s : {"src_bytes_log", "dst_bytes_log", "land", "wrong_fragment", "urgent", "count", "srv_count",
                       "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                       "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                       "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                       "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                       "dst_host_rerror_rate", "dst_host_srv_rerror_rate"})
            n.push_back(s);
        return n;
    }();
    return names;
}

std::vector<float> nidsFeatureVector(const ConnRecord& c) {
    std::vector<float> v;
    v.reserve(nidsFeatureNames().size());
    v.push_back(static_cast<float>(std::log1p(std::max(0.0, c.duration))));
    v.push_back(c.protocol == "tcp");
    v.push_back(c.protocol == "udp");
    v.push_back(c.protocol == "icmp");
    bool known = false;
    for (auto& s : kServices) {
        bool m = (c.service == s);
        if (m) known = true;
        v.push_back(m ? 1.0f : 0.0f);
    }
    if (!known) v[4 + kServices.size() - 1] = 1.0f;  // -> "other"
    for (auto& f : kFlags) v.push_back(c.flag == f ? 1.0f : 0.0f);
    for (double x : {std::log1p(std::max(0.0, c.srcBytes)), std::log1p(std::max(0.0, c.dstBytes)),
                     static_cast<double>(c.land), static_cast<double>(c.wrongFragment), static_cast<double>(c.urgent),
                     c.count, c.srvCount, c.serrorRate, c.srvSerrorRate, c.rerrorRate, c.srvRerrorRate, c.sameSrvRate,
                     c.diffSrvRate, c.srvDiffHostRate, c.dstHostCount, c.dstHostSrvCount, c.dstHostSameSrvRate,
                     c.dstHostDiffSrvRate, c.dstHostSameSrcPortRate, c.dstHostSrvDiffHostRate, c.dstHostSerrorRate,
                     c.dstHostSrvSerrorRate, c.dstHostRerrorRate, c.dstHostSrvRerrorRate})
        v.push_back(static_cast<float>(x));
    return v;
}

static bool isSynError(const std::string& f) { return f == "S0" || f == "S1" || f == "S2" || f == "S3"; }
static bool isRejError(const std::string& f) { return f == "REJ"; }

void computeTrafficFeatures(std::vector<ConnRecord>& conns) {
    std::sort(conns.begin(), conns.end(), [](const ConnRecord& a, const ConnRecord& b) { return a.startTime < b.startTime; });
    // Time-based: connections in the past 2 seconds (window ends at this record's start).
    size_t winStart = 0;
    for (size_t i = 0; i < conns.size(); ++i) {
        auto& c = conns[i];
        while (winStart < i && conns[winStart].startTime < c.startTime - 2.0) ++winStart;
        double cnt = 0, srv = 0, serr = 0, rerr = 0, sameSrv = 0, srvSerr = 0, srvRerr = 0, srvDiffHost = 0;
        for (size_t k = winStart; k <= i; ++k) {
            auto& o = conns[k];
            if (o.dstIp == c.dstIp) {
                cnt++;
                if (isSynError(o.flag)) serr++;
                if (isRejError(o.flag)) rerr++;
                if (o.service == c.service) sameSrv++;
            }
            if (o.service == c.service) {
                srv++;
                if (isSynError(o.flag)) srvSerr++;
                if (isRejError(o.flag)) srvRerr++;
                if (o.dstIp != c.dstIp) srvDiffHost++;
            }
        }
        c.count = std::min(cnt, 511.0);
        c.srvCount = std::min(srv, 511.0);
        c.serrorRate = cnt ? serr / cnt : 0;
        c.rerrorRate = cnt ? rerr / cnt : 0;
        c.sameSrvRate = cnt ? sameSrv / cnt : 0;
        c.diffSrvRate = cnt ? 1.0 - c.sameSrvRate : 0;
        c.srvSerrorRate = srv ? srvSerr / srv : 0;
        c.srvRerrorRate = srv ? srvRerr / srv : 0;
        c.srvDiffHostRate = srv ? srvDiffHost / srv : 0;
    }
    // Host-based: the last 100 connections (including this one).
    for (size_t i = 0; i < conns.size(); ++i) {
        auto& c = conns[i];
        size_t from = i >= 99 ? i - 99 : 0;
        double hostCnt = 0, hostSrv = 0, sameSrv = 0, sameSrcPort = 0, srvDiffHost = 0, serr = 0, srvSerr = 0,
               rerr = 0, srvRerr = 0;
        for (size_t k = from; k <= i; ++k) {
            auto& o = conns[k];
            if (o.dstIp == c.dstIp) {
                hostCnt++;
                if (o.service == c.service) sameSrv++;
                if (o.srcPort == c.srcPort) sameSrcPort++;
                if (isSynError(o.flag)) serr++;
                if (isRejError(o.flag)) rerr++;
            }
            if (o.service == c.service && o.dstPort == c.dstPort) {
                hostSrv++;
                if (o.dstIp != c.dstIp) srvDiffHost++;
                if (isSynError(o.flag)) srvSerr++;
                if (isRejError(o.flag)) srvRerr++;
            }
        }
        c.dstHostCount = std::min(hostCnt, 255.0);
        c.dstHostSrvCount = std::min(hostSrv, 255.0);
        c.dstHostSameSrvRate = hostCnt ? sameSrv / hostCnt : 0;
        c.dstHostDiffSrvRate = hostCnt ? 1.0 - c.dstHostSameSrvRate : 0;
        c.dstHostSameSrcPortRate = hostCnt ? sameSrcPort / hostCnt : 0;
        c.dstHostSrvDiffHostRate = hostSrv ? srvDiffHost / hostSrv : 0;
        c.dstHostSerrorRate = hostCnt ? serr / hostCnt : 0;
        c.dstHostRerrorRate = hostCnt ? rerr / hostCnt : 0;
        c.dstHostSrvSerrorRate = hostSrv ? srvSerr / hostSrv : 0;
        c.dstHostSrvRerrorRate = hostSrv ? srvRerr / hostSrv : 0;
    }
}

std::string kddService(const std::string& proto, uint16_t port, int icmpType) {
    if (proto == "icmp") {
        switch (icmpType) {
            case 8: return "eco_i";
            case 0: return "ecr_i";
            case 3: return "urp_i";
            default: return "other";
        }
    }
    static const std::unordered_map<uint16_t, std::string> tcp = {
        {80, "http"}, {8080, "http"}, {443, "http_443"}, {21, "ftp"}, {20, "ftp_data"}, {22, "ssh"},
        {23, "telnet"}, {25, "smtp"}, {587, "smtp"}, {79, "finger"}, {53, "domain"}, {110, "pop_3"},
        {143, "imap4"}, {111, "sunrpc"}, {113, "auth"}, {119, "nntp"}, {139, "netbios_ssn"},
        {445, "microsoft_ds"}, {513, "login"}, {514, "shell"}, {512, "exec"}, {389, "ldap"}, {194, "IRC"}};
    static const std::unordered_map<uint16_t, std::string> udp = {
        {53, "domain_u"}, {123, "ntp_u"}, {69, "tftp_u"}, {137, "netbios_ns"}, {138, "netbios_dgm"}};
    const auto& m = proto == "udp" ? udp : tcp;
    auto it = m.find(port);
    if (it != m.end()) return it->second;
    if (port >= 6000 && port <= 6063) return "X11";
    if (port >= 1024) return "private";
    return "other";
}

std::string kddAttackCategory(const std::string& label) {
    static const std::unordered_map<std::string, std::string> m = {
        {"normal", "normal"},
        {"back", "dos"}, {"land", "dos"}, {"neptune", "dos"}, {"pod", "dos"}, {"smurf", "dos"}, {"teardrop", "dos"},
        {"apache2", "dos"}, {"udpstorm", "dos"}, {"processtable", "dos"}, {"mailbomb", "dos"},
        {"satan", "probe"}, {"ipsweep", "probe"}, {"nmap", "probe"}, {"portsweep", "probe"}, {"mscan", "probe"},
        {"saint", "probe"},
        {"guess_passwd", "r2l"}, {"ftp_write", "r2l"}, {"imap", "r2l"}, {"phf", "r2l"}, {"multihop", "r2l"},
        {"warezmaster", "r2l"}, {"warezclient", "r2l"}, {"spy", "r2l"}, {"xlock", "r2l"}, {"xsnoop", "r2l"},
        {"snmpguess", "r2l"}, {"snmpgetattack", "r2l"}, {"httptunnel", "r2l"}, {"sendmail", "r2l"}, {"named", "r2l"},
        {"worm", "r2l"},
        {"buffer_overflow", "u2r"}, {"loadmodule", "u2r"}, {"rootkit", "u2r"}, {"perl", "u2r"}, {"sqlattack", "u2r"},
        {"xterm", "u2r"}, {"ps", "u2r"}};
    auto it = m.find(label);
    return it == m.end() ? "dos" : it->second;
}

}  // namespace cyberguard::features
