#pragma once
// Connection-record features for the Network Intrusion Detection System.
//
// We reproduce the subset of NSL-KDD features that can be derived from
// packet HEADERS (like Bro/Zeek connection logs): basic connection features
// plus the time-based (last 2 s) and host-based (last 100 connections)
// traffic statistics. The 13 "content" features (failed logins, root shells,
// ...) need payload inspection of 1998-era cleartext protocols and are
// deliberately excluded, so the model trained on NSL-KDD can score traffic we
// reconstruct from real pcap files with exactly the same feature vector.
#include <cstdint>
#include <string>
#include <vector>

namespace cyberguard::features {

struct ConnRecord {
    double startTime = 0;   // seconds
    double duration = 0;
    std::string protocol;   // tcp | udp | icmp
    std::string service;    // KDD service name (http, private, domain_u, ecr_i, ...)
    std::string flag;       // KDD/Bro conn state (SF, S0, REJ, RSTO, RSTR, SH, S1, S2, S3, OTH, RSTOS0)
    std::string srcIp, dstIp;
    uint16_t srcPort = 0, dstPort = 0;
    double srcBytes = 0, dstBytes = 0;
    uint64_t srcPackets = 0, dstPackets = 0;
    int land = 0, wrongFragment = 0, urgent = 0;
    long tag = -1;  // caller-defined id (e.g. flow index), untouched by feature code

    // traffic features (computed by computeTrafficFeatures or read from NSL-KDD)
    double count = 0, srvCount = 0, serrorRate = 0, srvSerrorRate = 0, rerrorRate = 0, srvRerrorRate = 0,
           sameSrvRate = 0, diffSrvRate = 0, srvDiffHostRate = 0, dstHostCount = 0, dstHostSrvCount = 0,
           dstHostSameSrvRate = 0, dstHostDiffSrvRate = 0, dstHostSameSrcPortRate = 0,
           dstHostSrvDiffHostRate = 0, dstHostSerrorRate = 0, dstHostSrvSerrorRate = 0,
           dstHostRerrorRate = 0, dstHostSrvRerrorRate = 0;
};

const std::vector<std::string>& nidsFeatureNames();
std::vector<float> nidsFeatureVector(const ConnRecord& c);

// Fills the time-based and host-based traffic features for every record,
// following the KDD Cup '99 definitions. Records are sorted by startTime.
void computeTrafficFeatures(std::vector<ConnRecord>& conns);

// Port/protocol -> KDD service name.
std::string kddService(const std::string& proto, uint16_t dstPort, int icmpType);

// NSL-KDD label -> attack category (normal, dos, probe, r2l, u2r).
std::string kddAttackCategory(const std::string& label);
const std::vector<std::string>& nidsClasses();

}  // namespace cyberguard::features
