// Maps CyberGuard's internal threat categories to MITRE ATT&CK technique IDs.
// This is a static reference lookup (not a live ATT&CK Navigator integration)
// that satisfies the PRD's "MITRE ATT&CK mapping" innovation opportunity by
// giving every detected threat a standard, cross-referenceable vocabulary
// that a SOC analyst or a second tool can act on directly.
const MITRE_MAP = {
  phishing: [
    { id: 'T1566', name: 'Phishing' },
    { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
  ],
  malicious_url: [
    { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
    { id: 'T1583.001', name: 'Acquire Infrastructure: Domains' },
  ],
  deepfake: [
    { id: 'T1656', name: 'Impersonation' },
    { id: 'T1585', name: 'Establish Accounts' },
  ],
  impersonation: [
    { id: 'T1656', name: 'Impersonation' },
    { id: 'T1585.001', name: 'Establish Accounts: Social Media Accounts' },
  ],
  account_takeover: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1111', name: 'Multi-Factor Authentication Interception' },
  ],
  network_threat: [
    { id: 'T1046', name: 'Network Service Discovery' },
    { id: 'T1595', name: 'Active Scanning' },
  ],
  api_abuse: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1499', name: 'Endpoint Denial of Service' },
  ],
  data_exfiltration: [
    { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    { id: 'T1030', name: 'Data Transfer Size Limits (evasion of)' },
  ],
  insider_threat: [
    { id: 'T1078.001', name: 'Valid Accounts: Default Accounts (privilege misuse)' },
    { id: 'T1530', name: 'Data from Cloud Storage' },
  ],
  malware: [
    { id: 'T1204', name: 'User Execution' },
    { id: 'T1027', name: 'Obfuscated Files or Information' },
    { id: 'T1055', name: 'Process Injection' },
  ],
  technical_threat: [
    { id: 'T1595', name: 'Active Scanning' },
  ],
  // Network IDS categories
  dos: [
    { id: 'T1498', name: 'Network Denial of Service' },
    { id: 'T1499', name: 'Endpoint Denial of Service' },
  ],
  probe: [
    { id: 'T1046', name: 'Network Service Discovery' },
    { id: 'T1595', name: 'Active Scanning' },
  ],
  r2l: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1133', name: 'External Remote Services' },
  ],
  u2r: [
    { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
  ],
  c2: [
    { id: 'T1071', name: 'Application Layer Protocol' },
    { id: 'T1571', name: 'Non-Standard Port' },
  ],
  exfiltration: [
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
    { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
  ],
  policy: [
    { id: 'T1040', name: 'Network Sniffing' },
  ],
  network_anomaly: [
    { id: 'T1595', name: 'Active Scanning' },
  ],
};

function techniquesForCategory(category) {
  return MITRE_MAP[category] || [];
}

module.exports = { techniquesForCategory, MITRE_MAP };
