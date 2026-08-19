import { Check, FileText, Info, LockKey, ShieldCheck, X } from "@phosphor-icons/react";
import {
  DEMO_AI_RESPONSE,
  DEMO_LEDGER_DURATION,
  DEMO_LEDGER_ID,
  DEMO_LEDGER_INCLUDED_FIELDS,
  DEMO_LEDGER_MODEL,
  DEMO_LEDGER_PROMPT_HASH,
  DEMO_LEDGER_REGION,
  DEMO_LEDGER_REQUEST_ID,
  DEMO_LEDGER_RESPONSE_HASH,
  DEMO_LEDGER_TOKENS,
} from "../demo/demoState.js";
import { evidence, removedFields } from "../mockData.js";
import { Modal, Pill } from "./ui.jsx";

export function EvidenceModal({ selectedEvidence, onClose, demoMode, evidenceItems = [] }) {
  const records = demoMode ? evidence : evidenceItems.map((entry) => ({ id: entry.id, label: entry.type || "Local event", time: entry.captured || entry.time, type: entry.type || "Event", detail: entry.detail }));
  const all = selectedEvidence === "all";
  const item = records.find((entry) => entry.id === selectedEvidence);
  return (
    <Modal title={all ? "Local Evidence Index" : item?.label || "Evidence"} eyebrow={all ? `${records.length} LOCAL ITEMS` : item?.id} onClose={onClose} wide={all}>
      {all ? <div className="modal-evidence-list">{records.map((entry) => <article key={entry.id}><code>{entry.id}</code><div><strong>{entry.label}</strong><p>{entry.detail}</p><small>{entry.time} · {entry.type}</small></div><Pill tone="local">Local</Pill></article>)}{!records.length ? <p>No evidence records are available for the selected alert.</p> : null}</div> : <div className="evidence-detail"><div className="evidence-detail__icon"><FileText size={28} weight="duotone" /></div><p>{item?.detail || "The referenced evidence is not present in the current bounded event search."}</p><dl className="detail-list"><div><dt>Captured</dt><dd>{item?.time || "—"}</dd></div><div><dt>Type</dt><dd>{item?.type || "Local evidence reference"}</dd></div><div><dt>Storage</dt><dd>Customer-resident data plane</dd></div><div><dt>Integrity</dt><dd className="success-text">API-scoped reference</dd></div></dl><div className="info-note"><Info size={17} /><span>Raw evidence is available to authorized local analysts. It was not included in the AI transmission.</span></div></div>}
    </Modal>
  );
}

export function LedgerModal({ onClose, transmission, demoMode }) {
  if (!demoMode && !transmission) return <Modal title="View AI Transmission" eyebrow="NO TRANSMISSION" onClose={onClose}><div className="empty-assurance"><LockKey size={27} /><div><strong>No handoff recorded</strong><p>Start an investigation before inspecting its minimized outbound package.</p></div></div></Modal>;
  const item = transmission || {};
  const removed = demoMode ? removedFields.slice(0, 6) : [...new Set([...(item.fieldsRemoved || []), ...(item.fieldsTokenized || [])])];
  return (
    <Modal title="View AI Transmission" eyebrow={`${item.id || DEMO_LEDGER_ID} · ${item.status || "COMPLETED"}`} onClose={onClose} wide>
      <div className="ledger-hero"><div><ShieldCheck size={32} weight="duotone" /><span><strong>Zero-retention verified</strong><small>Policy evaluated locally before an outbound-only mutual TLS request.</small></span></div><Pill tone={item.result === "Failure" ? "high" : "completed"}>{item.result || "Success"} · {item.duration || DEMO_LEDGER_DURATION}</Pill></div>
      <div className="ledger-modal-grid">
        <section><span className="eyebrow">MINIMIZED EVIDENCE PACKAGE</span><h3>Included fields</h3><ul className="check-list">{demoMode ? DEMO_LEDGER_INCLUDED_FIELDS.map((field) => <li key={field}><Check size={15} />{field}</li>) : (item.fieldsIncluded || []).map((field) => <li key={field}><Check size={15} />{field}</li>)}</ul></section>
        <section><span className="eyebrow">STRICT REDACTION</span><h3>Removed or tokenized</h3><ul className="check-list check-list--removed">{removed.map((field) => <li key={field}><X size={15} />{field}</li>)}</ul></section>
      </div>
      <dl className="ledger-facts"><div><dt>Request</dt><dd>{item.requestId || DEMO_LEDGER_REQUEST_ID}</dd></div><div><dt>Policy</dt><dd>{item.mode || "policy-v1 / Strict"}</dd></div><div><dt>Provider / model</dt><dd>{item.model || DEMO_LEDGER_MODEL}</dd></div><div><dt>Region</dt><dd>{item.region || DEMO_LEDGER_REGION}</dd></div><div><dt>Tokens</dt><dd>{demoMode ? DEMO_LEDGER_TOKENS : `${item.inputTokens || 0} input / ${item.outputTokens || 0} output`}</dd></div><div><dt>Retention</dt><dd className="success-text">Zero-retention verified</dd></div><div><dt>Prompt hash</dt><dd><code>{item.promptHash ? `sha256:${item.promptHash.slice(0, 12)}…` : DEMO_LEDGER_PROMPT_HASH}</code></dd></div><div><dt>Response hash</dt><dd><code>{item.responseHash ? `sha256:${item.responseHash.slice(0, 12)}…` : DEMO_LEDGER_RESPONSE_HASH}</code></dd></div></dl>
      <div className="policy-proof"><LockKey size={18} /><p><strong>Fail-closed boundary:</strong> certificate, schema, redaction, region, or retention validation failure blocks the request. No raw logs, packet payloads, or direct identifiers crossed the boundary.</p></div>
    </Modal>
  );
}

export function AiResponseModal({ onClose, assessment, demoMode }) {
  const item = assessment || {};
  if (!demoMode && !assessment) return <Modal title="Structured AI Assessment" eyebrow="NOT AVAILABLE" onClose={onClose}><p>No validated assessment is available for this investigation.</p></Modal>;
  const fallback = demoMode ? DEMO_AI_RESPONSE : {};
  return (
    <Modal title="Structured AI Assessment" eyebrow="VALIDATED LOCALLY" onClose={onClose}>
      <div className="ai-response-score"><span>Assessment confidence</span><strong>{demoMode ? "87%" : `${Math.round(Number(item.confidence || 0) * 100)}%`}</strong><Pill tone="human">Requires human review</Pill></div>
      <dl className="detail-list"><div><dt>Classification</dt><dd>{item.classification || fallback.classification}</dd></div><div><dt>MITRE ATT&amp;CK</dt><dd>{item.mitre_techniques?.join(" · ") || fallback.mitre_techniques?.join(" · ")}</dd></div><div><dt>Evidence citations</dt><dd>{item.supporting_evidence_ids?.join(" · ") || fallback.supporting_evidence_ids?.join(" · ")}</dd></div></dl>
      <div className="response-copy"><h3>Summary</h3><p>{item.summary || fallback.summary}</p><h3>Allowed recommendations</h3><ul>{demoMode ? fallback.recommended_actions.map((action) => <li key={action}>{action}</li>) : (item.recommended_actions || []).map((action) => <li key={action}>{action.replaceAll("_", " ")}</li>)}</ul></div>
    </Modal>
  );
}
