import { ArrowRight, Bell, Briefcase, ChartLineUp, Notebook, ShieldCheck } from "@phosphor-icons/react";
import { MetricCard, PageHeader, Pill, Severity } from "../components/ui.jsx";

export function OverviewPage({ alerts, cases, overview, sensors: sensorItems, onNavigate, onOpenAlert, dataSource, demoMode }) {
  const events = overview?.events;
  const sensorCount = overview?.sensors?.length ?? sensorItems.length;
  return (
    <div className="standard-page">
      <PageHeader
        eyebrow={demoMode ? "DEMO DEPLOYMENT" : "CUSTOMER DEPLOYMENT"}
        title="Local Defense Overview"
        description="Local detection and investigation activity. AI access is optional and controlled by policy."
        actions={<Pill tone="local">{dataSource === "backend" ? "Local API connected" : "Local demo data"}</Pill>}
      />
      <div className="metrics-grid">
        <MetricCard label="Recent indexed events" value={events === undefined ? "—" : String(events)} detail={`Up to 1,000 records · ${sensorCount} enrolled sensors`} icon={ChartLineUp} />
        <MetricCard label="Completed investigations" value={overview ? String(overview.completed_investigations ?? 0) : "—"} detail="Persisted in the local data plane" icon={Notebook} tone="violet" />
        <MetricCard label="Loaded open alerts" value={String(alerts.filter((item) => item.status !== "Closed").length)} detail={`${alerts.filter((item) => ["High", "Critical"].includes(item.severity)).length} high or critical`} icon={Bell} tone="orange" />
        <MetricCard label="Loaded cases" value={String(cases.length)} detail="Recent records available to your role" icon={Briefcase} tone="green" />
      </div>
      <div className="overview-grid">
        <section className="panel overview-alerts">
          <div className="panel-heading"><div><span className="eyebrow">PRIORITY QUEUE</span><h2>Alerts requiring review</h2></div><button className="text-button" onClick={() => onNavigate("Alerts")}>View all <ArrowRight size={15} /></button></div>
          <div className="compact-list">
            {alerts.slice(0, 3).map((alert) => (
              <button className="compact-alert" key={alert.id} onClick={() => onOpenAlert(alert.id)}>
                <Severity level={alert.severity} />
                <span className="compact-alert__main"><strong>{alert.title}</strong><small>{alert.source} · {alert.detector}</small></span>
                <span className="compact-alert__time">{alert.lastSeen.slice(11, 16)} UTC</span>
                <ArrowRight size={17} />
              </button>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading"><div><span className="eyebrow">LOCAL OPERATIONS</span><h2>Detection continuity</h2></div><Pill tone="completed">Operational</Pill></div>
          <div className="continuity-card">
            <ShieldCheck size={38} weight="duotone" />
            <h3>Detection remains local</h3>
            <p>Alerts, evidence, timelines, and cases continue working without AI or cloud connectivity.</p>
          </div>
          <div className="system-bars">
            <div><span>Sensor availability</span><b>99.98%</b><i style={{ width: "99%" }} /></div>
            <div><span>Local storage</span><b>63%</b><i style={{ width: "63%" }} /></div>
            <div><span>LLM availability</span><b>Available</b><i style={{ width: "96%" }} /></div>
          </div>
        </section>
      </div>
    </div>
  );
}
