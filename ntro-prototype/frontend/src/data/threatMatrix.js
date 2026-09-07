// The six threat classes named by the problem statement (NTRO Problem
// 26145), and this prototype's actual coverage of each -- not an
// aspirational list. `status: 'implemented'` means a real detector runs
// end-to-end in backend/detectors/ and has been validated (see
// ../../ML_MODELS.md and recon-ml-poc/README.md for the numbers);
// `status: 'designed'` means the architecture and the upstream data this
// detector would need already exist (Zeek already logs the required
// fields), but no detector/model has been built for it yet in this
// prototype. Nothing here is rendered as "coming soon" fluff -- each
// `designed` row names exactly what already exists to build on.
export const THREAT_MATRIX = [
  {
    key: 'ddos',
    label: 'Volumetric / Protocol DDoS',
    accent: 'var(--threat-ddos)',
    approach: 'Flow-level rate and source-IP entropy statistics',
    status: 'implemented',
    detail: 'RandomForestClassifier, GroupKFold-validated (F1 0.994 vs. 0.921 for the original fixed-rate threshold). backend/detectors/ddos.py.',
  },
  {
    key: 'c2',
    label: 'Botnet C2 Beaconing',
    accent: 'var(--threat-c2)',
    approach: 'Periodicity and inter-arrival interval analysis',
    status: 'implemented',
    detail: 'RandomForestClassifier, range-gated to its validated input region (F1 0.966 vs. 0.739 for the original CV-threshold rule). backend/detectors/c2.py.',
  },
  {
    key: 'recon',
    label: 'Reconnaissance / Port Scanning',
    accent: 'var(--threat-recon)',
    approach: 'Fan-out patterns (unique ports/hosts) from a single source',
    status: 'implemented',
    detail: 'RandomForestClassifier, GroupKFold-validated (F1 1.000 vs. 0.984 for the original fixed-threshold rule). backend/detectors/recon.py.',
  },
  {
    key: 'dga',
    label: 'DGA Domains / DNS Tunnelling',
    accent: 'var(--threat-dga)',
    approach: 'Entropy / n-gram analysis of DNS query names',
    status: 'designed',
    detail: 'Zeek’s dns.log already extracts the query name, type, and NXDOMAIN flag this needs. No detector or model built yet in this prototype.',
  },
  {
    key: 'tls',
    label: 'Malware in Encrypted Sessions',
    accent: 'var(--threat-tls)',
    approach: 'JA3/JA4 TLS fingerprint + flow-stats ML (no decryption)',
    status: 'designed',
    detail: 'Zeek’s ssl.log already extracts the ClientHello fields (cipher suites, extensions, SNI) JA3/JA4 needs. No detector or model built yet in this prototype.',
  },
  {
    key: 'exfil',
    label: 'Data Exfiltration',
    accent: 'var(--threat-exfil)',
    approach: 'Asymmetric flow-volume / byte-ratio analysis',
    status: 'designed',
    detail: 'Zeek’s conn.log already records the per-connection byte and duration fields this needs. No detector or model built yet in this prototype.',
  },
]
