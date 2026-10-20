import { useEffect, useState } from "react";
import {
  Bell,
  Briefcase,
  ChartLineUp,
  CloudCheck,
  Database,
  GearSix,
  HardDrives,
  LockKey,
  MagnifyingGlass,
  Notebook,
  PaperPlaneTilt,
  Scroll,
  ShieldCheck,
  ShieldChevron,
  SquaresFour,
  User,
} from "@phosphor-icons/react";
import { trustStatus } from "../dashboardState.js";

export const navItems = [
  { name: "Overview", icon: SquaresFour },
  { name: "Alerts", icon: Bell },
  { name: "Investigation", icon: Notebook },
  { name: "Cases", icon: Briefcase },
  { name: "Response", icon: ShieldCheck },
  { name: "Traffic", icon: ChartLineUp },
  { name: "Log Search", icon: MagnifyingGlass },
  { name: "Sensors", icon: HardDrives },
  { name: "Detection Rules", icon: ShieldChevron },
  { name: "AI Transmissions", icon: PaperPlaneTilt },
  { name: "Integrations", icon: CloudCheck },
  { name: "Audit", icon: Scroll },
  { name: "System Settings", icon: GearSix },
];

export function TrustStrip({ dataSource, demoMode, health, observedAt, policy, user, onSignOut }) {
  const [time, setTime] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setTime(new Date());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const timeLabel = time.toISOString().replace("T", " ").slice(0, 19);
  const status = trustStatus({ demoMode, dataSource, health, observedAt, policy }, time.getTime());

  return (
    <header className="trust-strip">
      <div className="node-identity">
        <ShieldCheck size={22} weight="regular" aria-hidden="true" />
        <strong>{demoMode ? "Demo node" : "Local API"}</strong>
        <span className={`health-dot${status.healthy ? "" : " health-dot--unavailable"}`} />
        <span>{status.node}</span>
      </div>
      <div className="sovereignty-chip">
        <ShieldCheck size={16} weight="duotone" aria-hidden="true" />
        <strong>DATA SOVEREIGNTY:</strong>
        <span>Raw security data stays customer-local</span>
      </div>
      <div className="trust-metrics">
        <span><CloudCheck size={15} weight="fill" /> <b>DATA:</b> {status.data}</span>
        <span><LockKey size={15} /> <b>AI POLICY:</b> {status.policy}</span>
        <span className="clock"><b>TIME:</b> {timeLabel} UTC</span>
        {user ? <button className="session-button" onClick={onSignOut} disabled={!onSignOut} title={onSignOut ? "Sign out" : user.name}><User size={14} /> {user.name || user.email || "Analyst"}</button> : null}
      </div>
    </header>
  );
}

export function Sidebar({ activePage, onNavigate, alertCount }) {
  return (
    <aside className="sidebar">
      <div className="sidebar__label">LOCAL DEFENSE</div>
      <nav aria-label="Primary navigation">
        {navItems.map(({ name, icon: Icon }) => (
          <button
            className={`nav-item ${activePage === name ? "is-active" : ""}`}
            key={name}
            onClick={() => onNavigate(name)}
            title={name}
          >
            <Icon size={19} weight={activePage === name ? "duotone" : "regular"} />
            <span>{name}</span>
            {name === "Alerts" && Number.isInteger(alertCount) ? <span className="nav-badge">{alertCount}</span> : null}
          </button>
        ))}
      </nav>
      <div className="locality-note">
        <Database size={23} weight="duotone" />
        <div>
          <strong>Customer-local security data</strong>
          <p>Approved integrations use explicit data-sharing settings.</p>
        </div>
      </div>
    </aside>
  );
}
