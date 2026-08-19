import { useState } from "react";
import {
  ArrowLeft,
  ArrowSquareOut,
  Brain,
  CaretDown,
  ChartBar,
  Check,
  CheckCircle,
  CircleNotch,
  Cpu,
  DownloadSimple,
  FileText,
  LockKey,
  Play,
  Plus,
  ShieldCheck,
  ShieldChevron,
  Target,
  Warning,
} from "@phosphor-icons/react";
import { EvidenceChip, Pill, TimelineStep } from "../components/ui.jsx";
import { HOUR, MINUTE, demoStamp } from "../demo/time.js";
import { evidence, removedFields } from "../mockData.js";

const NARRATIVE = {
  hypothesis: demoStamp(65 * MINUTE + 19 * 1000), // "Logged: …"
  findingsCompleted: demoStamp(34 * MINUTE), // "Completed: …"
  assessmentRequested: demoStamp(33 * MINUTE),
  assessmentCompleted: demoStamp(32 * MINUTE + 48 * 1000),
  actionsGenerated: demoStamp(32 * MINUTE + 48 * 1000),
};

export const progressLabels = [
  "Retrieving alert context",
  "Collecting related local events",
  "Comparing behavior to baselines",
  "Building evidence timeline",
  "Redacting sensitive identifiers",
  "Applying transmission policy",
  "Validating structured assessment",
  "Saving locally and writing audit record",
];

export function LiveInvestigationNotebook({ alert, investigation, runState, onEvidence, onAiResponse, onBack }) {
  if (!alert) {
    return <main className="notebook"><button className="back-link" onClick={onBack}><ArrowLeft size={17} /> Back to Alerts</button><div className="empty-assurance"><ShieldCheck size={27} /><div><strong>Select an alert</strong><p>Open a local alert before starting an investigation.</p></div></div></main>;
  }
  const assessment = investigation?.assessment;
  const evidenceIds = assessment?.supporting_evidence_ids?.length ? assessment.supporting_evidence_ids : alert.evidenceIds;
  const features = Object.entries(alert.features || {});
  const baseline = Object.entries(alert.baseline || {});
  const completed = investigation?.status === "completed";
  const failed = investigation && !new Set(["running", "completed"]).has(investigation.status);
  return (
    <main className="notebook">
      <button className="back-link" onClick={onBack}><ArrowLeft size={17} /> Back to Alerts</button>
      <header className="alert-heading">
        <div className="alert-heading__title"><span className="alert-signal" /><h1>{alert.severity} Severity Alert: {alert.title}</h1><Pill tone="human">HUMAN REVIEW REQUIRED</Pill></div>
        <div className="alert-meta"><span><b>Alert ID:</b> {alert.id}</span><span><b>Created:</b> {alert.firstSeen}</span><span><b>Entity:</b> {alert.entityId}</span><span><b>Status:</b> {alert.status}</span></div>
      </header>

      {runState === "running" ? <div className="run-progress" role="status"><CircleNotch size={18} className="spin" /><div><strong>Investigation running locally</strong><span>The local API is collecting, minimizing, and validating evidence.</span></div><b>Active</b><i><span style={{ width: "72%" }} /></i></div> : null}
      {completed ? <div className="run-success"><CheckCircle size={18} weight="fill" /><strong>Investigation completed locally</strong><span>{evidenceIds.length} evidence references validated · assessment persisted by the local API</span></div> : null}
      {failed ? <div className="run-success run-success--warning"><Warning size={18} weight="fill" /><strong>Investigation finished without an AI assessment</strong><span>{investigation.errorCode || investigation.status}. The alert remains available for human review.</span></div> : null}

      <section className="timeline" aria-label="Investigation narrative">
        <TimelineStep number="1" icon={Target} title="Alert hypothesis" time={alert.firstSeen} active={runState === "running"}>
          <p>{alert.detector} identified {alert.title.toLowerCase()} for {alert.entityType || "entity"} {alert.entityId}. Local evidence must be reviewed before response.</p>
        </TimelineStep>
        <TimelineStep number="2" icon={Cpu} title="Automated local findings" tag="CUSTOMER-RESIDENT" time={investigation ? `Updated: ${investigation.updatedAt || alert.lastSeen}` : "Awaiting investigation"}>
          {features.length ? <ul className="finding-list">{features.map(([name, value]) => <li key={name}>{name.replaceAll("_", " ")}: <strong>{String(value)}</strong></li>)}</ul> : <p>The detector cited {alert.evidenceIds.length} local event{alert.evidenceIds.length === 1 ? "" : "s"}. Raw records remain inside the customer environment.</p>}
          <div className="evidence-row"><span>Evidence:</span>{alert.evidenceIds.slice(0, 8).map((id) => <EvidenceChip key={id} id={id} onClick={onEvidence} />)}{alert.evidenceIds.length > 8 ? <button className="inline-link" onClick={() => onEvidence("all")}>View all ({alert.evidenceIds.length})</button> : null}</div>
        </TimelineStep>
        <TimelineStep number="3" icon={ChartBar} title="Baseline comparison" time="Computed locally">
          {baseline.length ? <ul className="finding-list">{baseline.map(([name, value]) => <li key={name}>{name.replaceAll("_", " ")}: <strong>{String(value)}</strong></li>)}</ul> : <p>No mature baseline was attached to this detector result. The finding remains evidence-backed and requires analyst review.</p>}
        </TimelineStep>
        <TimelineStep number="4" icon={Brain} title="AI assessment (Zero-Retention)" tag={assessment ? "VALIDATED LOCALLY" : investigation ? investigation.status.toUpperCase() : "NOT STARTED"} tagTone={assessment ? "completed" : "human"} time={investigation?.updatedAt || "—"}>
          {assessment ? <div className="ai-result ai-result--live"><span>Structured assessment</span><strong>Confidence: {Math.round(Number(assessment.confidence || 0) * 100)}%</strong><p><b>{assessment.classification?.replaceAll("_", " ") || "Unclassified"}</b></p><p>{assessment.summary}</p><div><button className="outline-button outline-button--violet" onClick={onAiResponse}>View full AI response <ArrowSquareOut size={14} /></button>{evidenceIds[0] ? <EvidenceChip id={evidenceIds[0]} onClick={onEvidence} /> : null}</div></div> : <div className="handoff-card"><strong>{failed ? "Fail-closed boundary preserved" : "No assessment has been requested"}</strong><p>{failed ? "The gateway failure was recorded locally and did not close or delete the alert." : "Start an investigation to create a minimized, policy-approved evidence package."}</p></div>}
        </TimelineStep>
        <TimelineStep number="5" icon={ShieldChevron} title="Recommended actions" time={assessment ? "Returned in validated response" : "Awaiting assessment"} isLast>
          {assessment?.recommended_actions?.length ? <ol className="action-list">{assessment.recommended_actions.map((action) => <li key={action}>{action.replaceAll("_", " ")}</li>)}</ol> : <p>No automated action is authorized. Continue with human-led evidence review.</p>}
        </TimelineStep>
      </section>
    </main>
  );
}

export function InvestigationNotebook({ alert, investigation, demoMode, runState, runStep, onEvidence, onLedger, onAiResponse, onBack }) {
  if (!demoMode) return <LiveInvestigationNotebook alert={alert} investigation={investigation} runState={runState} onEvidence={onEvidence} onAiResponse={onAiResponse} onBack={onBack} />;
  return (
    <main className="notebook">
      <button className="back-link" onClick={onBack}><ArrowLeft size={17} /> Back to Alerts</button>
      <header className="alert-heading">
        <div className="alert-heading__title"><span className="alert-signal" /><h1>High Severity Alert: {alert.title}</h1><Pill tone="human">OPEN — HUMAN REVIEW REQUIRED</Pill></div>
        <div className="alert-meta"><span><b>Alert ID:</b> {alert.id}</span><span><b>First seen:</b> {alert.firstSeen}</span><span><b>Last seen:</b> {alert.lastSeen}</span><span><b>Status:</b> {alert.status}</span></div>
      </header>

      {runState === "running" ? (
        <div className="run-progress" role="status">
          <CircleNotch size={18} className="spin" />
          <div><strong>Investigation running locally</strong><span>{progressLabels[runStep] || progressLabels.at(-1)}</span></div>
          <b>{Math.round(((runStep + 1) / progressLabels.length) * 100)}%</b>
          <i><span style={{ width: `${((runStep + 1) / progressLabels.length) * 100}%` }} /></i>
        </div>
      ) : runState === "complete" ? (
        <div className="run-success"><CheckCircle size={18} weight="fill" /><strong>Investigation completed locally</strong><span>8 steps validated · 10 evidence items indexed · audit record written</span></div>
      ) : null}

      <section className="timeline" aria-label="Investigation narrative">
        <TimelineStep number="1" icon={Target} title="Hypothesis" time={`Logged: ${NARRATIVE.hypothesis}`} active={runState === "running" && runStep === 0}>
          <p>Unusual DNS TXT record volume and entropy to external domains suggests DNS tunneling (TUNNELBASE) used for covert data exfiltration.</p>
        </TimelineStep>
        <TimelineStep number="2" icon={Cpu} title="Automated Local Findings" tag="COMPLETED LOCALLY" time={`Completed: ${NARRATIVE.findingsCompleted}`} active={runState === "running" && runStep > 0 && runStep < 4}>
          <ul className="finding-list"><li>Observed DNS TXT volume: <strong>438</strong> over 28 minutes (P99 baseline: 24)</li><li>High-entropy TXT payloads to 3 domains not commonly used in baseline</li><li>Consistent periodicity every 60–61 seconds</li><li>Impacted host: WS-23-7F9C (10.20.14.37)</li><li>No detections of malware execution or persistence on endpoint</li><li>No data exfiltration via HTTP/HTTPS detected in this window</li></ul>
          <div className="evidence-row"><span>Evidence:</span>{["EV-1021", "EV-1022", "EV-1023", "EV-1024"].map((id) => <EvidenceChip key={id} id={id} onClick={onEvidence} />)}<button className="inline-link" onClick={() => onEvidence("all")}>View all evidence (10)</button></div>
        </TimelineStep>
        <TimelineStep number="3" icon={ChartBar} title="Baseline Comparison" time={`Completed: ${NARRATIVE.findingsCompleted}`} active={runState === "running" && runStep === 2}>
          <ul className="finding-list"><li>Metric: DNS TXT queries (count)</li><li>Observed: 438</li><li>Baseline p99 (7d): 24</li><li>Deviation: +1725%</li><li>Result: Significant deviation from established baseline</li></ul>
          <div className="evidence-row"><span>Evidence:</span>{["EV-1025", "EV-1026"].map((id) => <EvidenceChip key={id} id={id} onClick={onEvidence} />)}</div>
        </TimelineStep>
        <TimelineStep number="4" icon={Brain} title="AI Assessment (Zero-Retention)" tag="MINIMIZED HANDOFF" time={`Requested: ${NARRATIVE.assessmentRequested} · Completed: ${NARRATIVE.assessmentCompleted}`} active={runState === "running" && runStep >= 4 && runStep < 7}>
          <div className="assessment-flow">
            <div className="assessment-intro"><p>A minimized summary was generated locally with strict redaction and sent to the zero-retention model gateway for assessment.</p></div>
            <div className="handoff-card"><strong>Minimized Handoff Summary (Strict Redaction)</strong><ul><li>Alert context and hypothesis</li><li>Aggregated metrics and statistical deviations</li><li>Non-sensitive domain features (hashed)</li><li>Timeline and counts (no raw records)</li><li>Excluded: raw logs, PCAP, payloads, IPs, hostnames, credentials, or identifiers</li></ul></div>
            <div className="gateway"><span className="flow-arrow">→</span><div className="gateway-lock"><LockKey size={25} /></div><span className="flow-arrow">→</span><strong>Zero-Retention<br />Model Gateway</strong><small>Fail-Closed</small></div>
            <div className="ai-result"><span>AI Assessment Result</span><strong>Confidence: 87%</strong><p>Likely Technique: DNS Tunneling<br /><b>MITRE ATT&amp;CK:</b> T1071.004</p><p>Behavioral patterns are consistent with DNS tunneling: high-volume, high-entropy TXT queries with periodicity and low baseline precedent.</p><div><button className="outline-button outline-button--violet" onClick={onAiResponse}>View full AI response <ArrowSquareOut size={14} /></button><EvidenceChip id="EV-1027" onClick={onEvidence} /></div></div>
          </div>
        </TimelineStep>
        <TimelineStep number="5" icon={ShieldChevron} title="Recommended Actions" time={`Generated: ${NARRATIVE.actionsGenerated}`} isLast active={runState === "running" && runStep === 7}>
          <ol className="action-list"><li>Contain: Request approval to block identified domains at perimeter and endpoint.</li><li>Investigate: Review affected host (WS-23-7F9C) for user activity and processes during window.</li><li>Validate: Hunt for DNS tunneling indicators across environment using provided observables.</li><li>Monitor: Increase alerting sensitivity for DNS TXT anomalies for 48 hours.</li></ol>
          <div className="evidence-row"><span>Evidence:</span>{["EV-1028", "EV-1029"].map((id) => <EvidenceChip key={id} id={id} onClick={onEvidence} />)}</div>
        </TimelineStep>
      </section>
    </main>
  );
}

export function EvidenceRail({ onEvidence, onLedger, demoMode, evidenceItems = [], transmission }) {
  const visibleEvidence = demoMode ? evidence : evidenceItems.map((item) => ({
    id: item.id,
    label: item.type || "Local event",
    time: item.captured || item.time,
    detail: item.detail,
    type: item.type,
  }));
  const removed = demoMode ? removedFields : [...new Set([
    ...(transmission?.fieldsRemoved || []),
    ...(transmission?.fieldsTokenized || []),
  ])];
  return (
    <aside className="evidence-rail">
      <section className="rail-section">
        <header><h2>Evidence Index</h2><button className="inline-link" onClick={() => onEvidence("all")}>View all</button></header>
        <div className="evidence-index">{visibleEvidence.map((item) => <button key={item.id} onClick={() => onEvidence(item.id)}><code>{item.id}</code><span><strong>{item.label}</strong><small>{item.time}</small></span></button>)}{!visibleEvidence.length ? <p className="rail-empty">Evidence details load from the selected alert.</p> : null}</div>
      </section>
      <section className="rail-section ledger-summary">
        <header><h2>Transmission Ledger</h2><button className="inline-link" onClick={onLedger}>View ledger</button></header>
        {demoMode || transmission ? <dl><div><dt>Status:</dt><dd className="success-text">{transmission?.status || "Completed"}</dd></div><div><dt>Mode:</dt><dd>{transmission?.mode || "Zero-Retention (Strict)"}</dd></div><div><dt>Retention:</dt><dd>{transmission?.retentionMode === "zero" ? "None" : "None"}</dd></div><div><dt>Direction:</dt><dd>{transmission?.direction || "Outbound (Minimized Only)"}</dd></div><div><dt>Bytes Transmitted:</dt><dd>{transmission?.bytes || "3.71 KB"}</dd></div><div><dt>Time:</dt><dd>{transmission?.time || "2026-08-05 14:12:31 UTC"}</dd></div><div><dt>Duration:</dt><dd>{transmission?.duration || "17s"}</dd></div><div><dt>Result:</dt><dd>{transmission?.result || "Success"}</dd></div><div><dt>Fail State:</dt><dd className="success-text">Fail-Closed</dd></div></dl> : <p className="rail-empty">No external transmission is recorded for this alert.</p>}
      </section>
      <section className="rail-section removed-fields">
        <header><h2>Fields Removed (Strict Redaction)</h2><button className="inline-link" onClick={onLedger}>View list</button></header>
        <ul>{removed.map((field) => <li key={field}><Check size={15} weight="bold" />{field}</li>)}</ul>
        {!removed.length ? <p className="rail-empty">Redaction details appear after an investigation.</p> : null}
      </section>
      <div className="rail-policy"><span>Policy: Enforce</span><span>Boundary: Local → Zero-Retention Gateway</span></div>
    </aside>
  );
}

export function ActionDock({ runState, runStep, onStart, onLedger, onExport, actionMenuOpen, setActionMenuOpen, onStatus, onCreateCase }) {
  return (
    <footer className="action-dock">
      <button className={`start-button ${runState === "complete" ? "is-complete" : ""}`} onClick={onStart} disabled={runState === "running"}>
        {runState === "running" ? <CircleNotch size={24} className="spin" /> : runState === "complete" ? <CheckCircle size={24} weight="fill" /> : <Play size={24} weight="fill" />}
        <span><strong>{runState === "running" ? `Running step ${runStep + 1} of 8` : runState === "complete" ? "Investigation complete" : "Start investigation"}</strong><small>{runState === "running" ? progressLabels[runStep] : runState === "complete" ? "Local findings and assessment ready" : "Begin guided workflow"}</small></span>
        <CaretDown size={18} />
      </button>
      <button className="dock-button" onClick={onLedger}><FileText size={23} /><span><strong>View transmission ledger</strong><small>Review all minimized handoffs</small></span><ArrowSquareOut size={16} /></button>
      <span className="dock-spacer" />
      <button className="dock-button dock-button--compact" onClick={onExport}><DownloadSimple size={23} /><span><strong>Export investigation</strong><small>Local report (JSON)</small></span></button>
      <div className="action-menu-wrap">
        <button className="dock-button dock-button--action" onClick={() => setActionMenuOpen((open) => !open)} aria-expanded={actionMenuOpen}><DownloadSimple size={23} /><span><strong>Take action</strong><small>Approve, escalate, or close</small></span><CaretDown size={17} /></button>
        {actionMenuOpen ? <div className="action-menu">
          <button onClick={() => onStatus("Acknowledged")}><CheckCircle size={17} /><span><strong>Acknowledge alert</strong><small>Keep investigation open</small></span></button>
          <button onClick={() => onStatus("Closed")}><ShieldCheck size={17} /><span><strong>Close as reviewed</strong><small>Record analyst decision</small></span></button>
          <button onClick={onCreateCase}><Plus size={17} /><span><strong>Create incident case</strong><small>Escalate for human response</small></span></button>
        </div> : null}
      </div>
    </footer>
  );
}

export function InvestigationPage(props) {
  return (
    <div className="investigation-shell">
      <div className="investigation-scroll">
        <InvestigationNotebook {...props} />
        <EvidenceRail onEvidence={props.onEvidence} onLedger={props.onLedger} demoMode={props.demoMode} evidenceItems={props.evidenceItems} transmission={props.transmission} />
      </div>
      <ActionDock {...props} />
    </div>
  );
}
