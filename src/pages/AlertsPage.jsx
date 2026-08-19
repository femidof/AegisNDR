import { useState } from "react";
import { ArrowRight, FunnelSimple, MagnifyingGlass, Notebook, ShieldCheck } from "@phosphor-icons/react";
import { PageHeader, Severity, StatusBadge } from "../components/ui.jsx";

export function AlertsPage({ alerts, selectedAlertId, onSelect, onInvestigate, onStatusChange }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const filtered = alerts.filter((alert) => {
    const matchesQuery = `${alert.title} ${alert.id} ${alert.source} ${alert.detector}`.toLowerCase().includes(query.toLowerCase());
    return matchesQuery && (severity === "All severities" || alert.severity === severity);
  });
  const selected = alerts.find((alert) => alert.id === selectedAlertId) || alerts[0];

  return (
    <div className="standard-page alerts-page">
      <PageHeader eyebrow="LOCAL ALERT QUEUE" title="Alerts" description="Review locally generated detections and begin an evidence-backed investigation." />
      <div className="toolbar">
        <label className="search-control"><MagnifyingGlass size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search alert, entity, detector…" /></label>
        <label className="select-control"><FunnelSimple size={17} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All severities</option><option>High</option><option>Medium</option><option>Low</option></select></label>
        <span className="result-count">{filtered.length} alerts · Updated 14:32 UTC</span>
      </div>
      <div className="split-view">
        <section className="panel table-panel">
          <div className="data-table data-table--alerts">
            <div className="table-row table-row--header"><span>Severity</span><span>Alert</span><span>Entity</span><span>Status</span><span>Last seen</span></div>
            {filtered.map((alert) => (
              <button className={`table-row ${selectedAlertId === alert.id ? "is-selected" : ""}`} key={alert.id} onClick={() => onSelect(alert.id)}>
                <Severity level={alert.severity} />
                <span><strong>{alert.title}</strong><small>{alert.id}</small></span>
                <span><strong>{alert.source}</strong><small>{alert.sourceIp}</small></span>
                <StatusBadge status={alert.status} />
                <span>{alert.lastSeen.slice(11, 16)} UTC</span>
              </button>
            ))}
            {!filtered.length ? <div className="table-empty">No alerts match the current filters.</div> : null}
          </div>
        </section>
        {selected ? <aside className="panel alert-preview">
          <div className="alert-preview__top"><Severity level={selected.severity} /><span className="score-ring">{Math.round(selected.score * 100)}</span></div>
          <span className="eyebrow">{selected.id}</span>
          <h2>{selected.title}</h2>
          <p>{selected.detector} flagged statistically unusual behavior on {selected.source}.</p>
          <dl className="detail-list"><div><dt>Entity</dt><dd>{selected.source}</dd></div><div><dt>Destination</dt><dd>{selected.destination}</dd></div><div><dt>First seen</dt><dd>{selected.firstSeen}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div></dl>
          <label className="field-label">Update status<select value={selected.status} onChange={(event) => onStatusChange(selected.id, event.target.value)}><option>New</option><option>Acknowledged</option><option>Under Investigation</option><option>Closed</option></select></label>
          <button className="primary-button primary-button--full" onClick={() => onInvestigate(selected.id)}><Notebook size={18} /> Open investigation notebook <ArrowRight size={17} /></button>
        </aside> : <aside className="panel alert-preview"><div className="empty-assurance"><ShieldCheck size={27} /><div><strong>No local alerts</strong><p>The customer alert queue is currently empty.</p></div></div></aside>}
      </div>
    </div>
  );
}
