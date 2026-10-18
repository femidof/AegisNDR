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
import { DEMO_CLOCK_START } from "../demo/demoState.js";

export const navItems = [
  { name: "Overview", icon: SquaresFour },
  { name: "Alerts", icon: Bell, badge: 3 },
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

export function TrustStrip({ dataSource, user, onSignOut }) {
  const [time, setTime] = useState(DEMO_CLOCK_START);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setTime((current) => new Date(current.getTime() + 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const timeLabel = time.toISOString().replace("T", " ").slice(0, 19);

  return (
    <header className="trust-strip">
      <div className="node-identity">
        <ShieldCheck size={22} weight="regular" aria-hidden="true" />
        <strong>Local Node</strong>
        <span className="health-dot" />
        <span>Healthy</span>
      </div>
      <div className="sovereignty-chip">
        <ShieldCheck size={16} weight="duotone" aria-hidden="true" />
        <strong>DATA SOVEREIGNTY:</strong>
        <span>All data remains on customer infrastructure</span>
      </div>
      <div className="trust-metrics">
        <span><CloudCheck size={15} weight="fill" /> <b>DATA:</b> {dataSource === "backend" ? "Local API" : "Explicit Demo"}</span>
        <span><span className="health-dot" /> <b>LLM STATUS:</b> Available</span>
        <span><LockKey size={15} /> <b>POLICY:</b> Enforce</span>
        <span className="clock"><b>TIME:</b> {timeLabel} UTC</span>
        {user ? <button className="session-button" onClick={onSignOut} disabled={!onSignOut} title={onSignOut ? "Sign out" : user.name}><User size={14} /> {user.name || user.email || "Analyst"}</button> : null}
      </div>
    </header>
  );
}

export function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="sidebar__label">LOCAL DEFENSE</div>
      <nav aria-label="Primary navigation">
        {navItems.map(({ name, icon: Icon, badge }) => (
          <button
            className={`nav-item ${activePage === name ? "is-active" : ""}`}
            key={name}
            onClick={() => onNavigate(name)}
            title={name}
          >
            <Icon size={19} weight={activePage === name ? "duotone" : "regular"} />
            <span>{name}</span>
            {badge ? <span className="nav-badge">{badge}</span> : null}
          </button>
        ))}
      </nav>
      <div className="locality-note">
        <Database size={23} weight="duotone" />
        <div>
          <strong>All processing local</strong>
          <p>No customer data leaves this environment except minimized handoffs.</p>
        </div>
      </div>
    </aside>
  );
}
