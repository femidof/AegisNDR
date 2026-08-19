import { useState } from "react";
import { Plus, ShieldCheck, User } from "@phosphor-icons/react";
import { PageHeader, Pill, StatusBadge } from "../components/ui.jsx";

export function CasesPage({ cases, onCreateCase, onStatusChange, canCreate = true, selectedCaseId, onSelectCase, comments = [], onAddComment }) {
  const [commentBody, setCommentBody] = useState("");
  const selected = cases.find((item) => item.id === selectedCaseId) || cases[0];

  async function submitComment(event) {
    event.preventDefault();
    if (!selected || !commentBody.trim()) return;
    await onAddComment(selected.id, commentBody.trim());
    setCommentBody("");
  }

  return (
    <div className="standard-page">
      <PageHeader eyebrow="LOCAL CASE MANAGEMENT" title="Cases" description="Human-owned response work linked to immutable local evidence." actions={<button className="primary-button" onClick={onCreateCase} disabled={!canCreate}><Plus size={17} /> Create case</button>} />
      <section className="panel table-panel">
        <div className="data-table data-table--cases"><div className="table-row table-row--header"><span>Case</span><span>Priority</span><span>Owner</span><span>Status</span><span>Updated</span></div>{cases.map((item) => <div className={`table-row ${selected?.id === item.id ? "is-selected" : ""}`} key={item.id}><button className="case-title-button" onClick={() => onSelectCase(item.id)}><strong>{item.title}</strong><small>{item.id}</small></button><Pill tone={item.priority === "P1" ? "high" : "neutral"}>{item.priority}</Pill><span><User size={15} /> {item.owner}</span>{onStatusChange ? <select className="table-status-select" value={item.status} onChange={(event) => onStatusChange(item.id, event.target.value)}><option>Open</option><option>In progress</option><option>Resolved</option><option>Closed</option></select> : <StatusBadge status={item.status} />}<span>{item.updated}</span></div>)}{!cases.length ? <div className="table-empty">No incident cases have been created for this deployment.</div> : null}</div>
      </section>
      {selected ? <section className="panel case-thread"><div className="panel-heading"><div><span className="eyebrow">CASE ACTIVITY</span><h2>{selected.id} comments</h2></div><Pill tone="local">Local record</Pill></div><div className="comment-list">{comments.map((comment) => <article key={comment.comment_id}><header><strong>{comment.actor_id}</strong><time>{comment.created_at ? new Date(comment.created_at).toISOString().replace("T", " ").slice(0, 19) + " UTC" : ""}</time></header><p>{comment.body}</p></article>)}{!comments.length ? <p className="table-empty">No comments have been added to this case.</p> : null}</div><form className="comment-form" onSubmit={(event) => submitComment(event).catch(() => {})}><label className="field-label">Add analyst comment<textarea value={commentBody} onChange={(event) => setCommentBody(event.target.value)} maxLength={5000} placeholder="Record evidence review, ownership, or next steps…" /></label><button className="primary-button" disabled={!commentBody.trim()}><Plus size={16} /> Add comment</button></form></section> : null}
      <div className="empty-assurance"><ShieldCheck size={27} weight="duotone" /><div><strong>Case evidence is stored locally</strong><p>Case activity, approvals, and exports are recorded in the append-only audit history.</p></div></div>
    </div>
  );
}
