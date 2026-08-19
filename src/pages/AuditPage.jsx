import { Check } from "@phosphor-icons/react";
import { PageHeader, Pill } from "../components/ui.jsx";
import { auditEvents } from "../mockData.js";

export function AuditPage({ dynamicEvents = [], events: suppliedEvents, chainValid }) {
  const events = suppliedEvents || [...dynamicEvents, ...auditEvents];
  return (
    <div className="standard-page"><PageHeader eyebrow="APPEND-ONLY LOCAL RECORD" title="Audit" description="Policy decisions, analyst actions, evidence, and transmission events are preserved locally." actions={chainValid === undefined ? null : <Pill tone={chainValid ? "completed" : "high"}>{chainValid ? "Hash chain valid" : "Integrity check failed"}</Pill>} />
      <section className="panel audit-panel"><div className="audit-timeline">{events.map((event, index) => <article key={`${event.time}-${index}`}><span className="audit-marker"><Check size={13} weight="bold" /></span><div><header><strong>{event.action}</strong><Pill tone={event.outcome === "Success" || event.outcome === "Allowed" ? "completed" : "neutral"}>{event.outcome}</Pill></header><p><b>{event.actor}</b> · {event.object}</p><time>{event.time}</time></div></article>)}</div></section>
    </div>
  );
}
