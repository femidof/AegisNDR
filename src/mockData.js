// Deterministic demo data for the explicit `demo` dashboard mode. All
// timestamps are anchored to "now" at load time so the demo never goes stale;
// production rendering never reads this module.
import { DAY, HOUR, MINUTE, demoCompactDate, demoDate, demoStamp, demoTime } from "./demo/time.js";

export const PRIMARY_ALERT_ID = `A-${demoDate()}-000142`;

export const alerts = [
  {
    id: PRIMARY_ALERT_ID,
    title: "DNS Tunneling Detected",
    severity: "High",
    status: "Under Investigation",
    source: "WS-23-7F9C",
    sourceIp: "10.20.14.37",
    destination: "ns1.cdn-edge-sync.net",
    detector: "DNS tunneling signal",
    score: 0.94,
    firstSeen: demoStamp(65 * MINUTE),
    lastSeen: demoStamp(32 * MINUTE),
  },
  {
    id: `A-${demoDate()}-000137`,
    title: "Rare External Destination",
    severity: "Medium",
    status: "New",
    source: "ENG-LT-044",
    sourceIp: "10.20.8.44",
    destination: "45.77.219.18",
    detector: "New destination",
    score: 0.78,
    firstSeen: demoStamp(80 * MINUTE),
    lastSeen: demoStamp(78 * MINUTE),
  },
  {
    id: `A-${demoDate()}-000131`,
    title: "East-West Port Scan",
    severity: "Medium",
    status: "Acknowledged",
    source: "OPS-JUMP-02",
    sourceIp: "10.20.2.18",
    destination: "10.20.32.0/24",
    detector: "Port scan",
    score: 0.81,
    firstSeen: demoStamp(97 * MINUTE),
    lastSeen: demoStamp(95 * MINUTE),
  },
  {
    id: `A-${demoDate()}-000128`,
    title: "Outbound Traffic Spike",
    severity: "Low",
    status: "Closed",
    source: "BACKUP-03",
    sourceIp: "10.20.5.63",
    destination: "s3.us-east-1.amazonaws.com",
    detector: "Traffic spike",
    score: 0.62,
    firstSeen: demoStamp(110 * MINUTE),
    lastSeen: demoStamp(105 * MINUTE),
  },
];

export const evidence = [
  { id: "EV-1021", label: "DNS TXT volume timeseries", time: demoStamp(64 * MINUTE), type: "Timeseries", detail: "438 TXT queries observed across the investigation window; P99 baseline is 24." },
  { id: "EV-1022", label: "Indexed TXT queries (hashed)", time: demoStamp(64 * MINUTE), type: "Query sample", detail: "Query labels were one-way hashed locally before indexing; 413 unique high-entropy labels." },
  { id: "EV-1023", label: "Entropy analysis results", time: demoStamp(63 * MINUTE), type: "Analysis", detail: "Median subdomain entropy measured 4.82 bits/character, above the 3.40 policy threshold." },
  { id: "EV-1024", label: "Periodicity analysis", time: demoStamp(63 * MINUTE), type: "Analysis", detail: "Query intervals cluster between 60 and 61 seconds with 0.92 periodicity confidence." },
  { id: "EV-1025", label: "Baseline model snapshot", time: demoStamp(55 * MINUTE), type: "Baseline", detail: "Host and peer-group baseline generated locally from the previous 30 days." },
  { id: "EV-1026", label: "Deviation calculation details", time: demoStamp(55 * MINUTE), type: "Calculation", detail: "Observed TXT query count is 1,725% above the P99 baseline." },
  { id: "EV-1027", label: "AI assessment response", time: demoStamp(33 * MINUTE), type: "AI response", detail: "Zero-retention assessment returned 87% confidence for likely DNS tunneling." },
  { id: "EV-1028", label: "Recommended containment list", time: demoStamp(33 * MINUTE), type: "Recommendation", detail: "Block suspicious domains, isolate the source host, and monitor TXT anomalies for 48 hours." },
  { id: "EV-1029", label: "Hunting query pack", time: demoStamp(33 * MINUTE), type: "Hunt", detail: "Locally executable queries for DNS tunneling indicators across peer endpoints." },
  { id: "EV-1030", label: "All local findings bundle", time: demoStamp(32 * MINUTE), type: "Bundle", detail: "Signed manifest of local findings and evidence references. Raw records remain local." },
];

export const ledgerEntries = [
  {
    id: `TX-${demoCompactDate()}-0041`,
    time: demoStamp(33 * MINUTE),
    purpose: "Alert assessment",
    status: "Completed",
    mode: "Zero-Retention (Strict)",
    direction: "Outbound (Minimized Only)",
    bytes: "3.71 KB",
    duration: "17s",
    result: "Success",
    failState: "Fail-Closed",
    model: "Secure Reasoning Gateway",
  },
  {
    id: `TX-${demoCompactDate()}-0038`,
    time: demoStamp(100 * MINUTE),
    purpose: "Port scan triage",
    status: "Completed",
    mode: "Zero-Retention (Strict)",
    direction: "Outbound (Minimized Only)",
    bytes: "2.94 KB",
    duration: "11s",
    result: "Success",
    failState: "Fail-Closed",
    model: "Secure Reasoning Gateway",
  },
  {
    id: `TX-${demoCompactDate()}-0035`,
    time: demoStamp(150 * MINUTE),
    purpose: "Behavior summary",
    status: "Blocked by policy",
    mode: "Zero-Retention (Strict)",
    direction: "None",
    bytes: "0 B",
    duration: "0s",
    result: "Denied",
    failState: "Fail-Closed",
    model: "Not contacted",
  },
];

export const removedFields = [
  "Raw logs and event records",
  "PCAP and packet payloads",
  "Domain names (replaced with one-way hashes)",
  "IP addresses",
  "Hostnames and user identifiers",
  "File content and process command lines",
  "Credentials and secrets",
  "Any direct identifiers or sensitive content",
];

export const sensors = [
  { name: "core-span-01", type: "Zeek + Suricata", site: "New York DC", status: "Healthy", eps: "4,812", lastSeen: "8s ago" },
  { name: "edge-dns-01", type: "DNS telemetry", site: "New York DC", status: "Healthy", eps: "1,204", lastSeen: "4s ago" },
  { name: "branch-west-02", type: "Zeek", site: "Portland Office", status: "Healthy", eps: "931", lastSeen: "12s ago" },
  { name: "cloud-vpc-prod", type: "VPC Flow Logs", site: "AWS us-east-1", status: "Degraded", eps: "2,118", lastSeen: "3m ago" },
];

export const trafficRows = [
  { time: demoTime(32 * MINUTE), source: "10.20.14.37", destination: "ns1.cdn-edge-sync.net", protocol: "DNS/TXT", bytes: "1.8 KB", verdict: "Suspicious" },
  { time: demoTime(33 * MINUTE), source: "10.20.14.37", destination: "ns1.cdn-edge-sync.net", protocol: "DNS/TXT", bytes: "1.6 KB", verdict: "Suspicious" },
  { time: demoTime(34 * MINUTE), source: "10.20.14.37", destination: "ns2.cdn-edge-sync.net", protocol: "DNS/TXT", bytes: "1.7 KB", verdict: "Suspicious" },
  { time: demoTime(35 * MINUTE), source: "10.20.8.44", destination: "45.77.219.18", protocol: "TLS", bytes: "42.4 KB", verdict: "Review" },
  { time: demoTime(36 * MINUTE), source: "10.20.2.18", destination: "10.20.32.14", protocol: "TCP/445", bytes: "3.1 KB", verdict: "Allowed" },
];

export const initialCases = [
  { id: `CASE-${demoDate()}-0081`, title: "East-West port scan review", priority: "P2", owner: "Maya Chen", status: "In progress", updated: demoStamp(60 * MINUTE).slice(0, 16) + " UTC" },
  { id: `CASE-${demoDate()}-0079`, title: "Rare external destination validation", priority: "P3", owner: "Jon Bell", status: "Open", updated: demoStamp(150 * MINUTE).slice(0, 16) + " UTC" },
];

export const auditEvents = [
  { time: demoStamp(32 * MINUTE), actor: "Local Agent", action: "Evidence bundle signed", object: "EV-1030", outcome: "Success" },
  { time: demoStamp(33 * MINUTE), actor: "AI Gateway", action: "Zero-retention response received", object: `TX-${demoCompactDate()}-0041`, outcome: "Success" },
  { time: demoStamp(33 * MINUTE), actor: "Policy Engine", action: "Minimized handoff approved", object: PRIMARY_ALERT_ID, outcome: "Allowed" },
  { time: demoStamp(55 * MINUTE), actor: "Detection Engine", action: "Baseline deviation calculated", object: "EV-1026", outcome: "Success" },
];
