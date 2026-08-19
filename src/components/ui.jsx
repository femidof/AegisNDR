import { useEffect, useRef } from "react";
import { CheckCircle, CircleNotch, Warning, X } from "@phosphor-icons/react";

export function Pill({ children, tone = "neutral", className = "" }) {
  return <span className={`pill pill--${tone} ${className}`}>{children}</span>;
}

export function PageHeader({ eyebrow, title, description, actions }) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function MetricCard({ label, value, detail, icon: Icon, tone = "teal" }) {
  return (
    <article className="metric-card">
      <div className={`metric-icon metric-icon--${tone}`}><Icon size={19} weight="duotone" /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

export function Severity({ level }) {
  return <span className={`severity severity--${level.toLowerCase()}`}><span />{level}</span>;
}

export function StatusBadge({ status }) {
  const normalized = status.toLowerCase().replaceAll(" ", "-");
  return <Pill tone={normalized}>{status}</Pill>;
}

export function Modal({ title, eyebrow, onClose, children, wide = false }) {
  const panelRef = useRef(null);

  useEffect(() => {
    const handleKey = (event) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    panelRef.current?.focus();
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className={`modal-panel ${wide ? "modal-panel--wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={panelRef}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal-header">
          <div>
            {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
            <h2>{title}</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={19} /></button>
        </header>
        <div className="modal-body">{children}</div>
      </section>
    </div>
  );
}

export function Toast({ toast, onDismiss }) {
  if (!toast) return null;
  return (
    <button className={`toast toast--${toast.tone || "success"}`} onClick={onDismiss}>
      {toast.tone === "warning" ? <Warning size={19} weight="fill" /> : <CheckCircle size={19} weight="fill" />}
      <span><strong>{toast.title}</strong>{toast.message ? <small>{toast.message}</small> : null}</span>
      <X size={15} />
    </button>
  );
}

export function TimelineStep({ number, icon: Icon, title, tag, tagTone = "completed", time, children, isLast = false, active = false }) {
  return (
    <article className={`timeline-step ${active ? "is-running" : ""}`}>
      <div className="timeline-marker">
        <span className="step-number">{active ? <CircleNotch size={17} className="spin" /> : number}</span>
        {!isLast ? <span className="timeline-line" /> : null}
      </div>
      <div className="step-icon"><Icon size={27} weight="duotone" /></div>
      <div className="step-content">
        <header><div><h3>{title}</h3>{tag ? <Pill tone={tagTone}>{tag}</Pill> : null}</div><time>{time}</time></header>
        {children}
      </div>
    </article>
  );
}

export function EvidenceChip({ id, onClick }) {
  return <button className="evidence-chip" onClick={() => onClick(id)}>{id}</button>;
}
