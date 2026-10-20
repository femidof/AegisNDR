import { useEffect, useState } from "react";
import { ChartLineUp, Database, Pause, Play, WifiHigh } from "@phosphor-icons/react";
import { MetricCard, PageHeader, Pill } from "../components/ui.jsx";
import { trafficGroups, trafficSeries } from "../trafficData.js";

export function TrafficPage({ rows = [], api = null, demoMode = false }) {
  const [liveRows, setLiveRows] = useState([]);
  const [paused, setPaused] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(0);
  const [error, setError] = useState("");
  const [clock, setClock] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (demoMode || !api || paused) return undefined;
    let cancelled = false;
    let timer;
    async function refresh() {
      if (!document.hidden) {
        try {
          const next = await api.searchEvents({ start_time: new Date(Date.now() - 300_000).toISOString(), limit: 100 });
          if (!cancelled) { setLiveRows(next); setUpdatedAt(Date.now()); setError(""); }
        } catch (failure) {
          if (!cancelled) setError(failure.message || "The local event feed is unavailable.");
        }
      }
      if (!cancelled) timer = setTimeout(refresh, 3000);
    }
    refresh();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [api, demoMode, paused]);
  const visible = demoMode ? rows : liveRows;
  const fresh = updatedAt && clock - updatedAt < 10_000;
  const status = demoMode ? "Preview" : paused ? "Paused" : error ? "Disconnected" : fresh ? "Updating every 3 seconds" : "Waiting for the local API";
  const series = trafficSeries(visible, paused ? updatedAt : clock);
  const maximum = Math.max(1, ...series);
  const bytes = visible.reduce((sum, row) => sum + Math.max(0, Number(row.byteCount) || 0), 0);
  const protocols = trafficGroups(visible, "protocolValue");
  const destinations = trafficGroups(visible, "destination");
  const sources = trafficGroups(visible, "eventSource");
  return <div className="standard-page">
    <PageHeader eyebrow="CUSTOMER-LOCAL TRAFFIC" title="Traffic" description="Recent indexed observations from Suricata and Zeek. Live mode refreshes every three seconds; ingestion and flow completion can add delay." actions={<button className="outline-button" disabled={demoMode || !api} onClick={() => setPaused((value) => !value)}>{paused ? <Play size={16} /> : <Pause size={16} />}{paused ? "Resume" : "Pause"}</button>} />
    <div className="traffic-feed-status" role="status"><Pill tone={fresh && !paused && !error && !demoMode ? "local" : "human"}>{status}</Pill><span>{updatedAt ? `Last successful read ${new Date(updatedAt).toLocaleTimeString()} · ${Math.max(0, Math.floor((clock - updatedAt) / 1000))}s ago` : demoMode ? "Explicit sample data" : "No successful event read yet"}</span><span>Alerts only · No blocking action is taken from this view</span></div>
    {error ? <div className="info-note info-note--warning" role="alert">{error} Previously loaded observations may be stale.</div> : null}
    <div className="metrics-grid metrics-grid--three"><MetricCard label="Recent indexed observations" value={String(visible.length)} detail="Latest 100 events within five minutes" icon={ChartLineUp} /><MetricCard label="Sensor sources in this sample" value={String(sources.length)} detail={sources.map(([name]) => name).join(" · ") || "Waiting for events"} icon={WifiHigh} tone="orange" /><MetricCard label="Bytes represented" value={bytes ? `${bytes.toLocaleString()} B` : "—"} detail="Event metadata; not total link throughput" icon={Database} tone="green" /></div>
    <div className="traffic-visual-grid"><section className="panel traffic-chart"><div className="panel-heading"><div><span className="eyebrow">LAST 60 SECONDS</span><h2>Indexed observations</h2></div><Pill>{Math.max(...series)} peak / 5s</Pill></div><svg viewBox="0 0 720 160" role="img" aria-label="Observed events in twelve five-second intervals; bounded to the latest 100 records"><path d="M0 145H720 M0 75H720" className="traffic-chart-grid" />{series.map((count, index) => <rect key={index} x={index * 60 + 8} y={145 - count / maximum * 130} width="44" height={count / maximum * 130} rx="4"><title>{String(count) + " observations"}</title></rect>)}</svg><div className="traffic-chart-axis"><span>60 seconds ago</span><span>Now</span></div><p className="helper-text">This chart shows indexed events in the bounded sample, not packets per second or complete link volume.</p></section>
    <section className="panel traffic-breakdown"><div className="panel-heading"><div><span className="eyebrow">CURRENT SAMPLE</span><h2>Protocols</h2></div></div>{protocols.map(([name, count]) => <div className="traffic-group" key={name}><span>{name.toUpperCase()}</span><strong>{count}</strong><i style={{ width: `${count / Math.max(1, visible.length) * 100}%` }} /></div>)}{!protocols.length ? <p className="table-empty">Waiting for protocol metadata.</p> : null}<h3>Top destinations</h3>{destinations.map(([name, count]) => <div className="traffic-destination" key={name}><code title={name}>{name}</code><strong>{count}</strong></div>)}</section></div>
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">RECENT EVENTS</span><h2>Network activity</h2></div><Pill>{visible.length} / 100 loaded</Pill></div><div className="data-table data-table--traffic"><div className="table-row table-row--header"><span>Time</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Bytes</span><span>Detection</span></div>{visible.map((row, index) => <div className="table-row" key={row.id || `${row.time}-${index}`}><code title={row.eventTime}>{row.time}<small>{row.eventSource || (demoMode ? "Sample" : "Unknown sensor")}</small></code><code>{row.source}</code><span>{row.destination}</span><Pill>{row.protocol}</Pill><span>{row.bytes}</span><Pill tone={row.verdict === "Suspicious" ? "high" : "local"}>{row.verdict === "Suspicious" ? "Alert" : "Observed"}</Pill></div>)}{!visible.length ? <div className="table-empty">{demoMode ? "No sample events." : "Waiting for observations in the last five minutes. A connected API alone does not prove that capture is receiving traffic."}</div> : null}</div></section>
  </div>;
}
