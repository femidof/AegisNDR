import { ArrowSquareOut, LockKey, ShieldCheck } from "@phosphor-icons/react";
import { PageHeader, Pill, StatusBadge } from "../components/ui.jsx";
import { ledgerEntries } from "../mockData.js";

export function TransmissionsPage({ onLedger, entries = ledgerEntries }) {
  return (
    <div className="standard-page"><PageHeader eyebrow="AUDITABLE AI BOUNDARY" title="AI Transmissions" description="Every minimized evidence package crossing the customer boundary is policy-evaluated and recorded." actions={<Pill tone="local"><LockKey size={13} /> Zero-retention enforced</Pill>} />
      <section className="trust-callout"><div><ShieldCheck size={28} weight="duotone" /><span><strong>No customer security data leaves the environment</strong><small>without explicit policy evaluation, minimization, and auditable transmission.</small></span></div><button className="outline-button outline-button--violet" onClick={onLedger}>View AI Transmission <ArrowSquareOut size={15} /></button></section>
      <section className="panel table-panel"><div className="data-table data-table--transmissions"><div className="table-row table-row--header"><span>Request</span><span>Purpose</span><span>Policy / mode</span><span>Payload</span><span>Result</span><span>Time</span></div>{entries.map((entry) => <button className="table-row" key={entry.id} onClick={() => onLedger(entry)}><span><strong>{entry.id}</strong><small>{entry.direction}</small></span><span>{entry.purpose}</span><span><strong>{entry.mode}</strong><small>{entry.failState}</small></span><code>{entry.bytes}</code><StatusBadge status={entry.status} /><span>{entry.time.slice(11, 19)} UTC</span></button>)}{!entries.length ? <div className="table-empty">No AI transmission has crossed the customer boundary.</div> : null}</div></section>
    </div>
  );
}
