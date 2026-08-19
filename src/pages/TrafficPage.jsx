import { ChartLineUp, Database, WifiHigh } from "@phosphor-icons/react";
import { MetricCard, PageHeader, Pill } from "../components/ui.jsx";
import { trafficRows } from "../mockData.js";

export function TrafficPage({ rows = trafficRows }) {
  const bytes = rows.reduce((total, row) => total + Number(row.byteCount || 0), 0);
  const dns = rows.filter((row) => row.eventType?.includes("dns") || row.protocolValue?.toLowerCase() === "dns").length;
  return (
    <div className="standard-page"><PageHeader eyebrow="LOCAL NETWORK TELEMETRY" title="Traffic" description="Normalized flow and DNS telemetry retained inside the customer-resident data plane." />
      <div className="metrics-grid metrics-grid--three"><MetricCard label="Recent indexed events" value={String(rows.length)} detail="Current bounded API result" icon={ChartLineUp} /><MetricCard label="DNS events" value={String(dns)} detail="Within the current result" icon={WifiHigh} tone="orange" /><MetricCard label="Bytes represented" value={bytes ? `${bytes.toLocaleString()} B` : "—"} detail="Normalized event metadata" icon={Database} tone="green" /></div>
      <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">RECENT EVENTS</span><h2>Network activity</h2></div><Pill tone="local">Live local index</Pill></div><div className="data-table data-table--traffic"><div className="table-row table-row--header"><span>Time</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Bytes</span><span>Verdict</span></div>{rows.map((row, index) => <div className="table-row" key={row.id || `${row.time}-${index}`}><code>{row.time}</code><code>{row.source}</code><span>{row.destination}</span><Pill>{row.protocol}</Pill><span>{row.bytes}</span><Pill tone={row.verdict === "Suspicious" ? "high" : row.verdict === "Review" ? "human" : "completed"}>{row.verdict}</Pill></div>)}{!rows.length ? <div className="table-empty">No recent network events are available.</div> : null}</div></section>
    </div>
  );
}
