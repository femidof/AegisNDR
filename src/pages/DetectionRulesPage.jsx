import { useEffect, useState } from "react";
import { Check, CircleNotch, LockKey, Plus, X } from "@phosphor-icons/react";
import { PageHeader, Pill } from "../components/ui.jsx";

export function RuleEditor({ rule, onUpdate, onDelete, canManage = false }) {
  const [thresholds, setThresholds] = useState(JSON.stringify(rule.thresholds || {}, null, 2));
  const [severity, setSeverity] = useState(rule.severity || "dynamic");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setThresholds(JSON.stringify(rule.thresholds || {}, null, 2));
    setSeverity(rule.severity || "dynamic");
  }, [rule]);

  async function save() {
    if (!canManage || saving) return;
    setSaving(true);
    setError("");
    try {
      await onUpdate(rule.rule_id, { thresholds: JSON.parse(thresholds), severity });
    } catch (failure) {
      setError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  return <article className="admin-record"><header><div><strong>{rule.name}</strong><small>{rule.rule_id} · {rule.schedule} · version {rule.version}</small></div><label className="compact-toggle"><input type="checkbox" checked={rule.enabled} disabled={!canManage} onChange={(event) => onUpdate(rule.rule_id, { enabled: event.target.checked })} /><span>{rule.enabled ? "Enabled" : "Disabled"}</span></label></header><p>{rule.description}</p><div className="admin-record__fields"><label className="field-label">Severity<select disabled={!canManage} value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="dynamic">Dynamic</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label><label className="field-label admin-record__json">Thresholds (JSON)<textarea value={thresholds} disabled={!canManage} onChange={(event) => setThresholds(event.target.value)} spellCheck="false" /></label></div>{error ? <p role="alert" className="helper-text">{error}</p> : null}<footer><button className="outline-button" onClick={() => save().catch(() => {})} disabled={saving || !canManage}>{saving ? <CircleNotch size={15} className="spin" /> : <Check size={15} />} Save tuning</button>{!rule.builtin ? <button className="text-button danger-text" disabled={!canManage} onClick={() => onDelete(rule.rule_id)}><X size={15} /> Delete</button> : <small>Built-in rules can be disabled but not deleted.</small>}</footer></article>;
}

export function DetectionRulesPage({ rules, suppressions, onCreateRule, onUpdateRule, onDeleteRule, onCreateSuppression, onUpdateSuppression, onDeleteSuppression, canManage = false }) {
  const [newRule, setNewRule] = useState({ name: "", detector_id: "port-scan-v1", schedule: "fast-10s" });
  const [suppression, setSuppression] = useState({ name: "", rule_id: "port-scan-v1", entity_id: "", reason: "", expires_at: "" });
  if (rules === null) return <div className="standard-page"><PageHeader eyebrow="SECURITY ADMIN" title="Detection Rules" description="Rule visibility requires the organization-scoped rules:read permission." /><div className="empty-assurance"><LockKey size={27} /><div><strong>Administrative access required</strong><p>Your current role cannot read or tune local detection rules.</p></div></div></div>;

  async function createRule(event) {
    event.preventDefault();
    if (!canManage) return;
    if (await onCreateRule({ ...newRule, description: "Custom local detector configuration", enabled: true, severity: "dynamic", thresholds: {} }) === false) return;
    setNewRule({ name: "", detector_id: "port-scan-v1", schedule: "fast-10s" });
  }

  async function createSuppression(event) {
    event.preventDefault();
    if (!canManage) return;
    if (await onCreateSuppression({ name: suppression.name, rule_id: suppression.rule_id, match: { entity_id: suppression.entity_id }, reason: suppression.reason, enabled: true, expires_at: suppression.expires_at ? new Date(suppression.expires_at).toISOString() : null }) === false) return;
    setSuppression({ name: "", rule_id: rules[0]?.rule_id || "port-scan-v1", entity_id: "", reason: "", expires_at: "" });
  }

  return <div className="standard-page"><PageHeader eyebrow="LOCAL DETECTION CONTROL" title="Detection Rules" description="Tune scheduled local detectors and narrowly suppress authorized activity. Changes apply without a cloud dependency." actions={<Pill tone="local">{rules.length} rules</Pill>} /><div className="admin-columns"><section><div className="section-heading"><span className="eyebrow">RULE TUNING</span><h2>Scheduled detectors</h2></div><form className="panel inline-admin-form" onSubmit={(event) => createRule(event).catch(() => {})}><label className="field-label">Custom rule name<input required value={newRule.name} onChange={(event) => setNewRule({ ...newRule, name: event.target.value })} placeholder="Branch scanner policy" /></label><label className="field-label">Detector<select value={newRule.detector_id} onChange={(event) => { const detector = event.target.value; const schedule = detector === "port-scan-v1" || detector === "suricata-conversion-v1" ? "fast-10s" : detector === "dns-tunneling-v1" ? "tunneling-5m" : "behavior-1m"; setNewRule({ ...newRule, detector_id: detector, schedule }); }}><option value="port-scan-v1">Port scan</option><option value="dns-volume-v1">DNS volume</option><option value="dns-tunneling-v1">DNS tunneling</option><option value="traffic-spike-v1">Traffic spike</option><option value="new-destination-v1">New destination</option><option value="suricata-conversion-v1">Suricata alerts</option></select></label><button className="primary-button" disabled={!canManage || !newRule.name.trim()}><Plus size={16} /> Add rule</button></form><div className="admin-record-list">{rules.map((rule) => <RuleEditor key={rule.rule_id} rule={rule} canManage={canManage} onUpdate={onUpdateRule} onDelete={onDeleteRule} />)}</div></section><section><div className="section-heading"><span className="eyebrow">NOISE CONTROL</span><h2>Suppressions</h2></div><form className="panel suppression-form" onSubmit={(event) => createSuppression(event).catch(() => {})}><label className="field-label">Name<input required value={suppression.name} onChange={(event) => setSuppression({ ...suppression, name: event.target.value })} placeholder="Approved scanner" /></label><label className="field-label">Rule<select value={suppression.rule_id} onChange={(event) => setSuppression({ ...suppression, rule_id: event.target.value })}>{rules.map((rule) => <option value={rule.rule_id} key={rule.rule_id}>{rule.name}</option>)}</select></label><label className="field-label">Entity ID<input required value={suppression.entity_id} onChange={(event) => setSuppression({ ...suppression, entity_id: event.target.value })} placeholder="10.0.4.21" /></label><label className="field-label">Reason<textarea required minLength={3} value={suppression.reason} onChange={(event) => setSuppression({ ...suppression, reason: event.target.value })} /></label><label className="field-label">Expires (optional)<input type="datetime-local" value={suppression.expires_at} onChange={(event) => setSuppression({ ...suppression, expires_at: event.target.value })} /></label><button className="primary-button" disabled={!canManage}><Plus size={16} /> Add suppression</button></form><div className="admin-record-list">{suppressions.map((item) => <article className="admin-record admin-record--compact" key={item.suppression_id}><header><div><strong>{item.name}</strong><small>{item.rule_id} · {item.match?.entity_id || "bounded match"}</small></div><label className="compact-toggle"><input type="checkbox" checked={item.enabled} disabled={!canManage} onChange={(event) => onUpdateSuppression(item.suppression_id, { enabled: event.target.checked })} /><span>{item.enabled ? "Active" : "Disabled"}</span></label></header><p>{item.reason}</p><footer><small>{item.expires_at ? `Expires ${item.expires_at}` : "No expiry"}</small><button className="text-button danger-text" disabled={!canManage} onClick={() => onDeleteSuppression(item.suppression_id)}><X size={15} /> Delete</button></footer></article>)}{!suppressions.length ? <div className="table-empty">No detection suppressions are configured.</div> : null}</div></section></div></div>;
}
