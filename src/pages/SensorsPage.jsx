import { HardDrives, ShieldCheck } from "@phosphor-icons/react";
import { PageHeader, Pill, StatusBadge } from "../components/ui.jsx";
import { sensors } from "../mockData.js";

export function SensorsPage({ items = sensors }) {
  return (
    <div className="standard-page"><PageHeader eyebrow="PROD-EAST-01 DEPLOYMENT" title="Sensors" description="Local collection and detection health. Cloud or LLM availability does not affect sensor operation." actions={<Pill tone="completed">{items.length} enrolled</Pill>} />
      <div className="sensor-grid">{items.map((sensor) => <article className="sensor-card" key={sensor.name}><header><div className="sensor-icon"><HardDrives size={22} weight="duotone" /></div><StatusBadge status={sensor.status} /></header><h2>{sensor.name}</h2><p>{sensor.type}</p><dl><div><dt>Site</dt><dd>{sensor.site}</dd></div><div><dt>Ingest rate</dt><dd>{sensor.eps} eps</dd></div><div><dt>Last heartbeat</dt><dd>{sensor.lastSeen}</dd></div></dl></article>)}</div>
      <div className="continuity-banner"><ShieldCheck size={25} weight="fill" /><div><strong>Detection continuity protected</strong><p>No default transfer of raw customer security telemetry to the vendor cloud.</p></div></div>
    </div>
  );
}
