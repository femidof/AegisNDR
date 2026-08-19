import { useEffect, useState } from "react";
import { Check, CloudCheck, Database, DownloadSimple, FileText, LockKey } from "@phosphor-icons/react";
import { PageHeader, Pill } from "../components/ui.jsx";

export function SettingsPage({ notify, policy, onSave, demoMode, systemSettings, onSaveSystemSettings, exports, selectedAlert, onRequestExport, onApproveExport, onDownloadExport, supportBundles, onCreateSupportBundle, onDownloadSupportBundle }) {
  const [retention, setRetention] = useState(30);
  const [rawRetention, setRawRetention] = useState(14);
  const [strict, setStrict] = useState(policy ? policy.level === "strict" : true);
  const [failClosed, setFailClosed] = useState(true);
  const [exportReason, setExportReason] = useState("Incident evidence requested for authorized security review");
  const [approvalReason, setApprovalReason] = useState("Approved for the documented incident response purpose");
  useEffect(() => {
    if (policy) setStrict(policy.level === "strict");
  }, [policy]);
  useEffect(() => {
    if (systemSettings) {
      setRetention(systemSettings.event_retention_days);
      setRawRetention(systemSettings.raw_evidence_retention_days);
    }
  }, [systemSettings]);
  async function save() {
    if (demoMode) {
      notify("Demo settings saved", "The explicit demo state was updated; no API write was attempted.");
      return;
    }
    await Promise.all([
      onSave({ level: strict ? "strict" : "balanced", enabled: true }),
      onSaveSystemSettings({ event_retention_days: Number(retention), raw_evidence_retention_days: Number(rawRetention) }),
    ]);
  }
  return (
    <div className="standard-page"><PageHeader eyebrow="SECURITY ADMIN" title="System Settings" description="Configure local retention, approved exports, support bundles, and the AI transmission boundary." />
      <div className="settings-grid"><section className="panel settings-card"><header><Database size={21} /><div><h2>Local data retention</h2><p>Customer-resident evidence and telemetry</p></div></header><label className="field-label">Indexed events (days)<input type="number" min="1" max="3650" value={retention} onChange={(event) => setRetention(event.target.value)} /></label><label className="field-label">Raw evidence (days)<input type="number" min="1" max="3650" value={rawRetention} onChange={(event) => setRawRetention(event.target.value)} /></label><p className="helper-text">Retention work runs locally. Audit records retain a minimum one-year policy.</p></section>
      <section className="panel settings-card"><header><LockKey size={21} /><div><h2>AI transmission policy</h2><p>Applied before the outbound-only mTLS gateway</p></div></header><label className="toggle-row"><span><strong>Strict redaction</strong><small>Remove identifiers, payloads, and raw records</small></span><input type="checkbox" checked={strict} onChange={(event) => setStrict(event.target.checked)} /></label><label className="toggle-row"><span><strong>Fail-closed</strong><small>Block transmission when any policy check fails</small></span><input type="checkbox" checked={failClosed} onChange={(event) => setFailClosed(event.target.checked)} disabled={!demoMode} /></label></section>
      <section className="panel settings-card"><header><CloudCheck size={21} /><div><h2>Model gateway</h2><p>Zero-retention verified · {policy?.region || "us-east-1"}</p></div></header><dl className="detail-list"><div><dt>Connection</dt><dd className="success-text">{policy?.enabled === false ? "Disabled" : "Available"}</dd></div><div><dt>Provider</dt><dd>{policy?.provider || "Secure gateway"}</dd></div><div><dt>Retention</dt><dd>{policy?.retention_mode === "zero" || !policy ? "None" : policy.retention_mode}</dd></div></dl></section></div>
      <div className="settings-actions"><button className="primary-button" onClick={() => save().catch((error) => notify("Settings were not saved", error.message, "warning"))}><Check size={17} /> Save local settings</button></div>
      {!demoMode ? <div className="settings-workflows"><section className="panel workflow-card"><div className="panel-heading"><div><span className="eyebrow">EXPLICIT APPROVAL</span><h2>Evidence exports</h2></div><Pill tone="human">Approval required</Pill></div><p>Request an immutable JSON evidence package. A user with evidence:export must explicitly approve it before download.</p><label className="field-label">Export purpose<textarea value={exportReason} onChange={(event) => setExportReason(event.target.value)} maxLength={500} /></label><button className="outline-button" disabled={!selectedAlert?.evidenceIds?.length} onClick={() => onRequestExport({ alert_id: selectedAlert.id, evidence_ids: selectedAlert.evidenceIds, reason: exportReason, format: "json" })}><DownloadSimple size={16} /> Request selected investigation export</button><label className="field-label">Approval justification<input value={approvalReason} onChange={(event) => setApprovalReason(event.target.value)} /></label><div className="artifact-list">{exports.map((item) => <article key={item.export_id}><div><strong>{item.export_id.slice(0, 12)}…</strong><small>{item.status} · {item.evidence_ids.length} evidence items · {item.requested_by}</small></div>{item.status === "pending_approval" ? <button className="outline-button" onClick={() => onApproveExport(item.export_id, approvalReason)}><Check size={14} /> Approve</button> : <button className="outline-button" onClick={() => onDownloadExport(item.export_id)}><DownloadSimple size={14} /> Download</button>}</article>)}{!exports.length ? <div className="table-empty">No evidence exports requested.</div> : null}</div></section><section className="panel workflow-card"><div className="panel-heading"><div><span className="eyebrow">PRIVACY-SAFE DIAGNOSTICS</span><h2>Support bundles</h2></div><Pill tone="local">No secrets</Pill></div><p>Generate local health, configuration, and audit diagnostics. Raw events, credentials, prompts, and evidence content are excluded.</p>{supportBundles === null ? <div className="empty-assurance"><LockKey size={22} /><div><strong>Administrator permission required</strong><p>Support bundle access requires deployments:manage.</p></div></div> : <><button className="outline-button" onClick={() => onCreateSupportBundle({ include_health: true, include_configuration: true, include_audit: true })}><FileText size={16} /> Generate support bundle</button><div className="artifact-list">{supportBundles.map((item) => <article key={item.bundle_id}><div><strong>{item.bundle_id.slice(0, 12)}…</strong><small>{item.size_bytes.toLocaleString()} bytes · expires {item.expires_at.slice(0, 16).replace("T", " ")} UTC</small></div><button className="outline-button" onClick={() => onDownloadSupportBundle(item.bundle_id)}><DownloadSimple size={14} /> Download</button></article>)}{!supportBundles.length ? <div className="table-empty">No support bundle has been generated.</div> : null}</div></>}</section></div> : null}
    </div>
  );
}
