import { useState } from "react";
import { CircleNotch, MagnifyingGlass, Warning } from "@phosphor-icons/react";
import { PageHeader, Pill } from "../components/ui.jsx";

export function LogSearchPage({ results, onSearch }) {
  const [criteria, setCriteria] = useState({ query: "", source: "", event_type: "", protocol: "", src_ip: "", dst_ip: "", start_time: "", end_time: "" });
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setSearching(true);
    setError("");
    const payload = Object.fromEntries(Object.entries(criteria).filter(([, value]) => value));
    for (const field of ["start_time", "end_time"]) {
      if (payload[field]) payload[field] = new Date(payload[field]).toISOString();
    }
    try {
      await onSearch(payload);
    } catch (searchError) {
      setError(searchError.message);
    } finally {
      setSearching(false);
    }
  }

  return (
    <div className="standard-page">
      <PageHeader eyebrow="TENANT-SCOPED LOCAL INDEX" title="Log Search" description="Search normalized Suricata and Zeek events without moving raw telemetry outside this deployment." actions={<Pill tone="local">Local query</Pill>} />
      <form className="panel search-builder" onSubmit={submit}>
        <label className="field-label search-builder__query">Search event content<input value={criteria.query} onChange={(event) => setCriteria({ ...criteria, query: event.target.value })} placeholder="Event ID, signature, DNS query, service…" /></label>
        <label className="field-label">Source<select value={criteria.source} onChange={(event) => setCriteria({ ...criteria, source: event.target.value })}><option value="">All sources</option><option value="zeek">Zeek</option><option value="suricata">Suricata</option></select></label>
        <label className="field-label">Event type<input value={criteria.event_type} onChange={(event) => setCriteria({ ...criteria, event_type: event.target.value })} placeholder="network.dns" /></label>
        <label className="field-label">Protocol<input value={criteria.protocol} onChange={(event) => setCriteria({ ...criteria, protocol: event.target.value })} placeholder="tcp" /></label>
        <label className="field-label">Source IP<input value={criteria.src_ip} onChange={(event) => setCriteria({ ...criteria, src_ip: event.target.value })} placeholder="10.0.4.21" /></label>
        <label className="field-label">Destination IP<input value={criteria.dst_ip} onChange={(event) => setCriteria({ ...criteria, dst_ip: event.target.value })} placeholder="203.0.113.40" /></label>
        <label className="field-label">From<input type="datetime-local" value={criteria.start_time} onChange={(event) => setCriteria({ ...criteria, start_time: event.target.value })} /></label>
        <label className="field-label">To<input type="datetime-local" value={criteria.end_time} onChange={(event) => setCriteria({ ...criteria, end_time: event.target.value })} /></label>
        <div className="search-builder__actions"><button type="button" className="outline-button" onClick={() => setCriteria({ query: "", source: "", event_type: "", protocol: "", src_ip: "", dst_ip: "", start_time: "", end_time: "" })}>Clear</button><button className="primary-button" disabled={searching}>{searching ? <CircleNotch size={17} className="spin" /> : <MagnifyingGlass size={17} />} Search local events</button></div>
      </form>
      {error ? <div className="info-note info-note--warning"><Warning size={17} /><span>{error}</span></div> : null}
      <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">SEARCH RESULTS</span><h2>{results.length} normalized events</h2></div><Pill tone="local">Bounded to 100</Pill></div><div className="data-table data-table--log-search"><div className="table-row table-row--header"><span>Time</span><span>Source</span><span>Destination</span><span>Type / sensor</span><span>Protocol</span><span>Detail</span></div>{results.map((row) => <div className="table-row" key={row.id}><code>{row.captured}</code><code>{row.srcIp || "—"}</code><code>{row.dstIp || row.destination}</code><span><strong>{row.type}</strong><small>{row.sensorId} · {row.eventSource}</small></span><Pill>{row.protocol || "—"}</Pill><span><strong>{row.detail}</strong><small>{row.id}</small></span></div>)}{!results.length ? <div className="table-empty">No events match the current local query.</div> : null}</div></section>
    </div>
  );
}
