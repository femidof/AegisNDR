// Demo-mode state and canned content, isolated from production rendering.
// The dashboard renders real API data unless it is launched in explicit
// `demo` mode; every literal below is used only by that demo path. Times are
// anchored to "now" at load time so the demonstration never appears stale.
import { HOUR, MINUTE, demoCompactDate, demoInstant, demoStamp } from "./time.js";

export const DEMO_CLOCK_START = demoInstant(32 * MINUTE + 18 * 1000);

export const DEMO_AUDIT_INVESTIGATION_COMPLETED = {
  time: demoStamp(30 * MINUTE),
  actor: "Local Agent",
  action: "Investigation completed",
  outcome: "Success",
};

export const DEMO_AUDIT_ALERT_STATUS = {
  time: demoStamp(29 * MINUTE),
  actor: "Maya Chen",
  action: "Alert status changed to ",
  outcome: "Success",
};

export const DEMO_AUDIT_CASE_CREATED = {
  time: demoStamp(28 * MINUTE),
  actor: "Maya Chen",
  action: "Incident case created",
  outcome: "Success",
};

export const DEMO_CASE_UPDATED_TIME = demoStamp(28 * MINUTE).slice(0, 16) + " UTC";
export const DEMO_CASE_PREFIX = `CASE-${demoStamp().slice(0, 10)}-`;

export const DEMO_EXPORT_ASSESSMENT = {
  classification: "likely_dns_tunneling",
  confidence: 0.87,
  mitre: "T1071.004",
  requires_human_review: true,
};

export const DEMO_LEDGER_ID = `TX-${demoCompactDate()}-0041`;
export const DEMO_LEDGER_REQUEST_ID = `REQ-${demoCompactDate()}-0418`;
export const DEMO_LEDGER_MODEL = "Secure Reasoning Gateway";
export const DEMO_LEDGER_REGION = "us-east-1";
export const DEMO_LEDGER_TOKENS = "684 input / 194 output";
export const DEMO_LEDGER_DURATION = "1.8 s";
export const DEMO_LEDGER_PROMPT_HASH = "sha256:1ca9…8fe2";
export const DEMO_LEDGER_RESPONSE_HASH = "sha256:8b42…19d0";
export const DEMO_LEDGER_INCLUDED_FIELDS = [
  "Alert type, severity, and hypothesis",
  "Categorical entity: workstation-7f2c",
  "Numeric feature and baseline values",
  "Evidence IDs and approved actions",
];

export const DEMO_AI_RESPONSE = {
  classification: "likely_dns_tunneling",
  mitre_techniques: ["T1071.004"],
  supporting_evidence_ids: ["EV-1021", "EV-1022", "EV-1023", "EV-1024", "EV-1026"],
  summary:
    "DNS TXT volume and entropy are strongly abnormal. Periodic high-entropy queries and minimal baseline precedent are consistent with covert DNS tunneling.",
  recommended_actions: [
    "Inspect the affected endpoint locally.",
    "Review DNS history and associated process activity.",
    "Request approval before containment or blocking.",
  ],
};
