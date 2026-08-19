import { createPortalApi, PortalApiError } from "./api.js";
import { LogtoPortalClient, OidcError, readPortalConfig } from "./oidc.js";

const root = document.querySelector("#app");
const toastRegion = document.querySelector("#toast-region");

const state = {
  view: (location.hash || "#overview").slice(1),
  session: null,
  deployments: [],
  enrollments: [],
  selected: null,
  loading: true,
};

let config;
let auth;
let api;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

function icon(name) {
  const paths = {
    overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    deployment: '<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01"/>',
    policy: '<path d="M12 3 4.5 6.2v5.2c0 4.8 3.1 8.1 7.5 9.6 4.4-1.5 7.5-4.8 7.5-9.6V6.2L12 3Z"/><path d="m9 12 2 2 4-4"/>',
    update: '<path d="M20 7v5h-5"/><path d="M4 17v-5h5"/><path d="M18.5 9A7 7 0 0 0 6.2 6.2L4 9M5.5 15A7 7 0 0 0 17.8 17.8L20 15"/>',
    support: '<path d="M4 13a8 8 0 1 1 16 0"/><path d="M4 13v4a2 2 0 0 0 2 2h2v-7H4ZM20 13v4a2 2 0 0 1-2 2h-2v-7h4Z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    server: '<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01M8 17h.01"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.overview}</svg>`;
}

function toast(title, message, type = "") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.innerHTML = `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span>`;
  toastRegion.append(node);
  setTimeout(() => node.remove(), 5200);
}

function status(value) {
  const normalized = String(value || "unknown").toLowerCase().replaceAll("_", "-");
  return `<span class="status ${escapeHtml(normalized)}">${escapeHtml(String(value || "unknown").replaceAll("_", " "))}</span>`;
}

function date(value) {
  if (!value) return "Never";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "Unknown" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function number(value) {
  return new Intl.NumberFormat(undefined, { notation: Number(value) > 999_999 ? "compact" : "standard", maximumFractionDigits: 1 }).format(Number(value || 0));
}

function can(permission) { return Boolean(state.session?.actor?.permissions?.includes(permission)); }

function navButton(view, label, glyph) {
  return `<button class="nav-button ${state.view === view ? "active" : ""}" data-view="${view}">${icon(glyph)}<span>${label}</span></button>`;
}

function shell(content) {
  const org = state.session.organization;
  const user = auth.getUser() || { name: "Cloud administrator" };
  const initials = user.name.split(/\s+/).slice(0, 2).map((item) => item[0]).join("").toUpperCase();
  return `
    <div class="console">
      <aside class="sidebar">
        <div class="logo"><div class="brand-mark"><span></span></div><div><strong>AegisNDR</strong><small>Cloud Console</small></div></div>
        <p class="nav-label">Manage</p>
        <nav class="nav" aria-label="Cloud console">
          ${navButton("overview", "Overview", "overview")}
          ${navButton("deployments", "Deployments", "deployment")}
          ${navButton("policy", "Entitlements & policy", "policy")}
          ${navButton("updates", "Software updates", "update")}
          ${navButton("support", "Support", "support")}
        </nav>
        <div class="boundary-note"><span class="lock">◈</span><strong>Metadata-only boundary</strong><p>Customer events, evidence, packet captures, and analyst work never appear in this console.</p></div>
      </aside>
      <main class="main">
        <header class="topbar">
          <div class="org-switcher"><span class="org-glyph">${escapeHtml(org.name[0] || "O")}</span><div><strong>${escapeHtml(org.name)}</strong><small>${escapeHtml(org.organization_id)}</small></div></div>
          <div class="account"><div class="account-copy"><strong>${escapeHtml(user.name)}</strong><small>${escapeHtml(state.session.actor.role.replaceAll("_", " "))}</small></div><button class="avatar" id="account-button" title="Sign out">${escapeHtml(initials || "AA")}</button></div>
        </header>
        <div class="content">${content}</div>
      </main>
      <nav class="mobile-nav" aria-label="Cloud console mobile navigation">
        ${navButton("overview", "Overview", "overview")}${navButton("deployments", "Deployments", "deployment")}${navButton("policy", "Policy", "policy")}${navButton("updates", "Updates", "update")}${navButton("support", "Support", "support")}
      </nav>
    </div>`;
}

function pageHead(eyebrow, title, description, action = "") {
  return `<div class="page-head"><div><p class="eyebrow">${escapeHtml(eyebrow)}</p><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></div>${action ? `<div class="head-actions">${action}</div>` : ""}</div>`;
}

function deploymentRows(items = state.deployments) {
  if (!items.length) return `<div class="empty"><div class="empty-icon">${icon("server")}</div><h3>No enrolled deployments</h3><p>Create an enrollment to connect the first customer-resident deployment. The single-use token expires after 15 minutes.</p>${can("deployments:manage") ? '<button class="primary" data-action="enroll">Create enrollment</button>' : ""}</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>Deployment</th><th>Status</th><th>Version</th><th>Sensors</th><th>Storage</th><th>Last seen</th></tr></thead><tbody>${items.map((item) => `
    <tr data-id="${escapeHtml(item.deployment_id)}">
      <td><div class="entity"><span class="entity-icon">${icon("server")}</span>${escapeHtml(item.name)}</div></td>
      <td>${status(item.status)}</td>
      <td><span class="mono">${escapeHtml(item.software.installed_version)}</span>${item.software.update_available ? ' &nbsp;<span class="status available">update</span>' : ""}</td>
      <td>${item.sensors.filter((sensor) => ["healthy", "online"].includes(sensor.status)).length}/${item.sensors.length || "—"}</td>
      <td>${item.health.storage_percent == null ? "—" : `${escapeHtml(item.health.storage_percent)}%`}</td>
      <td>${escapeHtml(date(item.last_seen))}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function metrics() {
  const sensors = state.deployments.flatMap((item) => item.sensors || []);
  const online = state.deployments.filter((item) => item.status === "online").length;
  const updates = state.deployments.filter((item) => item.software.update_available).length;
  const pending = state.enrollments.filter((item) => item.status === "pending").length;
  return `<section class="metrics">
    <article class="metric-card"><div class="metric-top"><span>Deployment fleet</span><span class="metric-icon">◇</span></div><div class="metric-value">${state.deployments.length}</div><div class="metric-foot">${online} reporting online</div></article>
    <article class="metric-card"><div class="metric-top"><span>Sensor health</span><span class="metric-icon">◉</span></div><div class="metric-value">${sensors.filter((item) => ["healthy", "online"].includes(item.status)).length}<span class="muted">/${sensors.length}</span></div><div class="metric-foot">Metadata status only</div></article>
    <article class="metric-card"><div class="metric-top"><span>Updates ready</span><span class="metric-icon">↻</span></div><div class="metric-value">${updates}</div><div class="metric-foot">Customer-controlled installation</div></article>
    <article class="metric-card"><div class="metric-top"><span>Pending enrollments</span><span class="metric-icon">＋</span></div><div class="metric-value">${pending}</div><div class="metric-foot">15-minute single-use tokens</div></article>
  </section>`;
}

function overview() {
  const org = state.session.organization;
  const action = can("deployments:manage") ? `<button class="primary" data-action="enroll">＋ &nbsp;New deployment</button>` : "";
  const averageStorage = state.deployments.length
    ? state.deployments.reduce((total, item) => total + Number(item.health.storage_percent || 0), 0) / state.deployments.length : 0;
  return `${pageHead("Fleet overview", "Operational control, without the security data", `Monitor ${org.name}'s deployments, software, and aggregate usage.`, action)}
    ${metrics()}
    <div class="grid-two">
      <section class="card"><div class="card-head"><div><h2>Deployment fleet</h2><p>Health, versions, and sensor state</p></div><button class="ghost" data-view="deployments">View all →</button></div>${deploymentRows()}</section>
      <div>
        <section class="card"><div class="card-head"><div><h2>Fleet capacity</h2><p>Aggregate operational telemetry</p></div></div><div class="card-body health-list">
          <div class="health-row"><div><strong>Average storage use</strong><small>Across reporting deployments</small></div><span>${averageStorage.toFixed(1)}%</span><div class="bar"><span style="width:${Math.min(100, averageStorage)}%"></span></div></div>
          <div class="health-row"><div><strong>Events processed</strong><small>Latest deployment aggregates</small></div><span>${number(state.deployments.reduce((total, item) => total + Number(item.usage?.events_processed || 0), 0))}</span></div>
          <div class="health-row"><div><strong>Protected assets</strong><small>Reported metering total</small></div><span>${number(state.deployments.reduce((total, item) => total + Number(item.usage?.protected_assets || 0), 0))}</span></div>
        </div></section>
        <section class="boundary-card"><strong>Customer data stays customer-side</strong><p>This cloud view is structurally limited to tenant IDs, health statuses, versions, capacity percentages, aggregate counts, licensing, and update state.</p><div class="boundary-tags"><span>No events</span><span>No evidence</span><span>No packet capture</span><span>No analyst notes</span></div></section>
      </div>
    </div>`;
}

function deploymentsView() {
  const action = can("deployments:manage") ? `<button class="primary" data-action="enroll">＋ &nbsp;Create enrollment</button>` : "";
  return `${pageHead("Infrastructure", "Deployments", "Enroll customer sites and monitor only the operational metadata they report.", action)}
    <section class="card"><div class="card-head"><div><h2>All deployments</h2><p>${state.deployments.length} enrolled · ${state.enrollments.filter((item) => item.status === "pending").length} pending</p></div></div>${deploymentRows()}</section>
    ${state.enrollments.length ? `<section class="card"><div class="card-head"><div><h2>Enrollment history</h2><p>Tokens themselves are never shown again</p></div></div><div class="table-wrap"><table><thead><tr><th>Site</th><th>Status</th><th>Channel</th><th>Created</th><th>Expires</th></tr></thead><tbody>${state.enrollments.map((item) => `<tr><td>${escapeHtml(item.deployment_name)}</td><td>${status(item.status)}</td><td>${escapeHtml(item.update_channel)}</td><td>${escapeHtml(date(item.created_at))}</td><td>${escapeHtml(date(item.expires_at))}</td></tr>`).join("")}</tbody></table></div></section>` : ""}`;
}

function deploymentDetail() {
  const item = state.selected;
  if (!item) return deploymentsView();
  const sensorContent = item.sensors.length ? item.sensors.map((sensor) => `<div class="sensor-row"><strong>${escapeHtml(sensor.sensor_id)}</strong>${status(sensor.status)}</div>`).join("") : '<p class="muted">No sensor status has been reported yet.</p>';
  return `${pageHead("Deployment", item.name, "Operational detail reported through the outbound deployment connector.", '<button class="secondary" data-action="back-deployments">← &nbsp;All deployments</button>')}
    <div class="split-detail"><div>
      <section class="card"><div class="card-head"><div><h2>Deployment health</h2><p>Last seen ${escapeHtml(date(item.last_seen))}</p></div>${status(item.status)}</div><div class="card-body detail-grid">
        <div class="detail-item"><span>Installed version</span><strong class="mono">${escapeHtml(item.software.installed_version)}</strong></div>
        <div class="detail-item"><span>Available version</span><strong class="mono">${escapeHtml(item.software.available_version)}</strong></div>
        <div class="detail-item"><span>Storage utilization</span><strong>${item.health.storage_percent == null ? "Not reported" : `${escapeHtml(item.health.storage_percent)}%`}</strong></div>
        <div class="detail-item"><span>Aggregate event count</span><strong>${number(item.health.event_count)}</strong></div>
        <div class="detail-item"><span>Certificate</span><strong>${escapeHtml(item.certificate.status)} · ${escapeHtml(date(item.certificate.expires_at))}</strong></div>
        <div class="detail-item"><span>Update channel</span><strong>${escapeHtml(item.software.update_channel)}</strong></div>
      </div></section>
      <section class="card"><div class="card-head"><div><h2>Aggregate usage</h2><p>Metering values contain no network identifiers</p></div></div><div class="card-body detail-grid">${Object.entries(item.usage || {}).map(([key, value]) => `<div class="detail-item"><span>${escapeHtml(key.replaceAll("_", " "))}</span><strong>${number(value)}</strong></div>`).join("") || '<p class="muted">Usage has not been reported.</p>'}</div></section>
    </div><div><section class="card"><div class="card-head"><div><h2>Sensors</h2><p>Status labels only</p></div></div><div class="card-body sensor-list">${sensorContent}</div></section>
      <section class="boundary-card"><strong>Deliberately absent</strong><p>No source or destination addresses, alerts, packet data, event rows, evidence, investigations, or user activity are available to this service.</p></section>
    </div></div>`;
}

function selectedDeployment() { return state.selected || state.deployments[0] || null; }

function policyView() {
  const item = selectedDeployment();
  if (!item) return `${pageHead("Configuration", "Entitlements & policy", "Control commercial access and the zero-retention model boundary.")}${deploymentRows([])}`;
  const ent = item.entitlements || {};
  const policy = item.model_policy || {};
  return `${pageHead("Configuration", "Entitlements & model policy", "Changes are organization-scoped and pulled outbound by the customer deployment.")}
    <div class="grid-two"><div>
      <form class="card" id="entitlements-form"><div class="card-head"><div><h2>Subscription entitlements</h2><p>${escapeHtml(item.name)}</p></div>${status(ent.subscription_status)}</div><div class="card-body"><div class="form-grid">
        <div class="field"><label for="edition">Edition</label><select id="edition" name="edition">${["enterprise", "dedicated", "regulated", "sovereign", "managed"].map((value) => `<option ${ent.edition === value ? "selected" : ""}>${value}</option>`).join("")}</select></div>
        <div class="field"><label for="subscription_status">Subscription status</label><select id="subscription_status" name="subscription_status">${["active", "grace", "suspended", "expired"].map((value) => `<option ${ent.subscription_status === value ? "selected" : ""}>${value}</option>`).join("")}</select></div>
        <div class="field"><label for="ai_monthly_limit">Monthly AI allowance</label><input id="ai_monthly_limit" name="ai_monthly_limit" type="number" min="0" value="${escapeHtml(ent.ai_monthly_limit || 0)}" /></div>
        <div class="field"><label for="protected_assets_limit">Protected asset limit</label><input id="protected_assets_limit" name="protected_assets_limit" type="number" min="0" value="${escapeHtml(ent.protected_assets_limit || 0)}" /></div>
        <div class="field"><label for="offline_grace_days">Offline grace days</label><input id="offline_grace_days" name="offline_grace_days" type="number" min="0" max="90" value="${escapeHtml(ent.offline_grace_days || 0)}" /></div>
        <div class="field"><label for="model_investigations">AI investigations</label><select id="model_investigations" name="model_investigations"><option value="true" ${ent.model_investigations ? "selected" : ""}>Enabled</option><option value="false" ${!ent.model_investigations ? "selected" : ""}>Disabled</option></select></div>
      </div>${can("entitlements:manage") ? '<div class="form-actions"><button class="primary" type="submit">Save entitlements</button></div>' : ""}</div></form>
      <form class="card" id="policy-form"><div class="card-head"><div><h2>Zero-retention model policy</h2><p>Requests fail closed when this contract cannot be enforced</p></div>${status(policy.enabled ? "active" : "disabled")}</div><div class="card-body"><div class="form-grid">
        <div class="field"><label for="level">Privacy level</label><select id="level" name="level">${["disabled", "strict", "balanced"].map((value) => `<option ${policy.level === value ? "selected" : ""}>${value}</option>`).join("")}</select></div>
        <div class="field"><label for="enabled">External model</label><select id="enabled" name="enabled"><option value="true" ${policy.enabled ? "selected" : ""}>Enabled</option><option value="false" ${!policy.enabled ? "selected" : ""}>Disabled</option></select></div>
        <div class="field"><label for="provider">Approved provider</label><input id="provider" name="provider" value="${escapeHtml(policy.provider)}" /></div>
        <div class="field"><label for="model">Approved model</label><input id="model" name="model" value="${escapeHtml(policy.model)}" /></div>
        <div class="field"><label for="region">Processing region</label><input id="region" name="region" value="${escapeHtml(policy.region)}" /></div>
        <div class="field"><label>Retention mode</label><input value="zero" disabled /><span class="field-hint">Cloud prompt and response persistence cannot be enabled.</span></div>
      </div>${can("policy:manage") ? '<div class="form-actions"><button class="primary" type="submit">Save model policy</button></div>' : ""}</div></form>
    </div><div><section class="card"><div class="card-head"><div><h2>Deployment</h2><p>Choose the policy target</p></div></div><div class="card-body"><div class="field"><label for="policy-deployment">Managed deployment</label><select id="policy-deployment">${state.deployments.map((deployment) => `<option value="${escapeHtml(deployment.deployment_id)}" ${deployment.deployment_id === item.deployment_id ? "selected" : ""}>${escapeHtml(deployment.name)}</option>`).join("")}</select></div></div></section>
      <section class="boundary-card"><strong>Local detection is resilient</strong><p>Suspending model entitlements does not stop customer-resident capture, detection, alerts, or access to prior investigations.</p></section>
    </div></div>`;
}

function updatesView() {
  return `${pageHead("Release management", "Software updates", "See version posture and select update channels. Installation remains customer-controlled.")}
    <section class="card"><div class="card-head"><div><h2>Fleet version posture</h2><p>Signed, digest-pinned update manifests</p></div></div><div class="table-wrap"><table><thead><tr><th>Deployment</th><th>Installed</th><th>Available</th><th>State</th><th>Channel</th><th>Published</th></tr></thead><tbody>${state.deployments.map((item) => `<tr><td><div class="entity">${escapeHtml(item.name)}</div></td><td class="mono">${escapeHtml(item.software.installed_version)}</td><td class="mono">${escapeHtml(item.software.available_version)}</td><td>${status(item.software.update_available ? "available" : item.software.update_status)}</td><td>${can("updates:manage") ? `<select class="channel-select" data-id="${escapeHtml(item.deployment_id)}">${["stable", "preview", "extended"].map((value) => `<option ${item.software.update_channel === value ? "selected" : ""}>${value}</option>`).join("")}</select>` : escapeHtml(item.software.update_channel)}</td><td>${escapeHtml(date(item.software.published_at))}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">No enrolled deployments.</td></tr>'}</tbody></table></div></section>
    <section class="boundary-card"><strong>No remote installation</strong><p>The console publishes signed update metadata. Customer administrators choose when to install or roll back; the vendor control plane does not initiate inbound access.</p></section>`;
}

function supportView() {
  const org = state.session.organization;
  const support = org.support || {};
  return `${pageHead("Customer care", "Support", "Maintain routing and service-level metadata without uploading security data.")}
    <div class="grid-two"><form class="card" id="support-form"><div class="card-head"><div><h2>Support profile</h2><p>${escapeHtml(org.name)}</p></div>${status(support.support_tier)}</div><div class="card-body"><div class="form-grid">
      <div class="field"><label for="org-name">Customer name</label><input id="org-name" name="name" value="${escapeHtml(org.name)}" /></div>
      <div class="field"><label for="support_email">Support contact</label><input id="support_email" name="support_email" type="email" value="${escapeHtml(support.support_email)}" /></div>
      <div class="field"><label for="support_tier">Support tier</label><select id="support_tier" name="support_tier">${["standard", "priority", "premium", "dedicated"].map((value) => `<option ${support.support_tier === value ? "selected" : ""}>${value}</option>`).join("")}</select></div>
      <div class="field"><label for="service_level">Service level</label><select id="service_level" name="service_level">${["business-hours", "24x5", "24x7"].map((value) => `<option ${support.service_level === value ? "selected" : ""}>${value}</option>`).join("")}</select></div>
      <div class="field full"><label for="external_customer_ref">External customer reference</label><input id="external_customer_ref" name="external_customer_ref" value="${escapeHtml(support.external_customer_ref)}" /><span class="field-hint">Use a contract or CRM reference—not an alert, host, event, or case identifier.</span></div>
    </div>${can("organizations:manage") || can("support:manage") ? '<div class="form-actions"><button class="primary" type="submit">Save support profile</button></div>' : ""}</div></form>
    <div><section class="card"><div class="card-head"><div><h2>Identity & access</h2><p>Organization users are managed through Logto</p></div></div><div class="card-body"><div class="detail-grid"><div class="detail-item"><span>Organization ID</span><strong class="mono">${escapeHtml(org.organization_id)}</strong></div><div class="detail-item"><span>Your role</span><strong>${escapeHtml(state.session.actor.role.replaceAll("_", " "))}</strong></div></div></div></section>
      <section class="boundary-card"><strong>Safe support workflow</strong><p>Only account, entitlement, health, version, capacity, and anonymized error-code metadata belongs here. Evidence exports and support bundles stay under explicit customer control.</p></section>
    </div></div>`;
}

function render() {
  if (!state.session) return;
  const view = state.view === "overview" ? overview() : state.view === "deployments" ? (state.selected ? deploymentDetail() : deploymentsView()) : state.view === "policy" ? policyView() : state.view === "updates" ? updatesView() : supportView();
  root.innerHTML = shell(view);
  wire();
}

function wire() {
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
    state.view = button.dataset.view;
    if (state.view !== "deployments") state.selected = null;
    location.hash = state.view;
    render();
  }));
  document.querySelectorAll('[data-action="enroll"]').forEach((button) => button.addEventListener("click", showEnrollmentModal));
  document.querySelector('[data-action="back-deployments"]')?.addEventListener("click", () => { state.selected = null; render(); });
  document.querySelectorAll("tbody tr[data-id]").forEach((row) => row.addEventListener("click", async () => {
    try { state.selected = await api.deployment(row.dataset.id); state.view = "deployments"; location.hash = "deployments"; render(); }
    catch (error) { showError(error); }
  }));
  document.querySelector("#account-button")?.addEventListener("click", async () => { location.assign(await auth.signOut()); });
  document.querySelector("#policy-deployment")?.addEventListener("change", async (event) => {
    try { state.selected = await api.deployment(event.target.value); render(); } catch (error) { showError(error); }
  });
  document.querySelector("#entitlements-form")?.addEventListener("submit", saveEntitlements);
  document.querySelector("#policy-form")?.addEventListener("submit", savePolicy);
  document.querySelector("#support-form")?.addEventListener("submit", saveSupport);
  document.querySelectorAll(".channel-select").forEach((select) => select.addEventListener("change", async () => {
    try { await api.updateChannel(select.dataset.id, select.value); await loadData(); toast("Update channel saved", "The deployment will receive the new signed manifest on its next refresh."); }
    catch (error) { showError(error); }
  }));
}

async function saveEntitlements(event) {
  event.preventDefault();
  const item = selectedDeployment();
  const values = Object.fromEntries(new FormData(event.currentTarget));
  values.ai_monthly_limit = Number(values.ai_monthly_limit);
  values.protected_assets_limit = Number(values.protected_assets_limit);
  values.offline_grace_days = Number(values.offline_grace_days);
  values.model_investigations = values.model_investigations === "true";
  try { await api.updateEntitlements(item.deployment_id, values); state.selected = await api.deployment(item.deployment_id); render(); toast("Entitlements saved", "The deployment will pull this metadata on its next refresh."); }
  catch (error) { showError(error); }
}

async function savePolicy(event) {
  event.preventDefault();
  const item = selectedDeployment();
  const values = Object.fromEntries(new FormData(event.currentTarget));
  values.enabled = values.enabled === "true";
  values.retention_mode = "zero";
  values.policy_id = item.model_policy.policy_id || "policy-v1";
  try { await api.updatePolicy(item.deployment_id, values); state.selected = await api.deployment(item.deployment_id); render(); toast("Model policy saved", "Zero-retention enforcement remains mandatory."); }
  catch (error) { showError(error); }
}

async function saveSupport(event) {
  event.preventDefault();
  try {
    const updated = await api.updateOrganization(Object.fromEntries(new FormData(event.currentTarget)));
    state.session.organization = updated;
    render();
    toast("Support profile saved", "Only approved account and routing metadata was stored.");
  } catch (error) { showError(error); }
}

function showEnrollmentModal() {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `<section class="modal" role="dialog" aria-modal="true" aria-labelledby="enroll-title"><div class="modal-head"><div><h2 id="enroll-title">Create deployment enrollment</h2><p>Generate a single-use, 15-minute token.</p></div><button class="icon-button" data-close aria-label="Close">${icon("close")}</button></div><form class="modal-body" id="enroll-form"><div class="form-grid"><div class="field full"><label for="deployment-name">Deployment name</label><input id="deployment-name" name="name" required minlength="2" maxlength="120" placeholder="New York edge" /></div><div class="field full"><label for="update-channel">Update channel</label><select id="update-channel" name="update_channel"><option>stable</option><option>preview</option><option>extended</option></select></div></div><div class="form-actions"><button class="secondary" type="button" data-close>Cancel</button><button class="primary" type="submit">Generate token</button></div></form></section>`;
  document.body.append(backdrop);
  backdrop.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => backdrop.remove()));
  backdrop.querySelector("#enroll-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.currentTarget.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      const result = await api.createDeployment(Object.fromEntries(new FormData(event.currentTarget)));
      backdrop.querySelector(".modal-body").innerHTML = `<div class="secret-box"><strong>Copy this token now</strong><code>${escapeHtml(result.enrollment_token)}</code><small>Expires ${escapeHtml(date(result.expires_at))}. It cannot be retrieved after this dialog closes.</small></div><p class="muted">After verifying the signed installer, run:</p><div class="command">sudo bash install.sh --enrollment-token '${escapeHtml(result.enrollment_token)}' --interface eth1</div><div class="form-actions"><button class="secondary" type="button" id="copy-token">Copy token</button><button class="primary" type="button" data-close>Done</button></div>`;
      backdrop.querySelector("#copy-token").addEventListener("click", async () => { await navigator.clipboard.writeText(result.enrollment_token); toast("Token copied", "Paste it only into the verified customer installer."); });
      backdrop.querySelector("[data-close]").addEventListener("click", async () => { backdrop.remove(); await loadData(); });
    } catch (error) { submit.disabled = false; showError(error); }
  });
  backdrop.querySelector("#deployment-name").focus();
}

function showError(error) {
  const known = error instanceof PortalApiError || error instanceof OidcError;
  toast("Request not completed", known ? error.message : "An unexpected error occurred.", "error");
}

async function loadData() {
  const [session, deployments, enrollments] = await Promise.all([api.session(), api.deployments(), api.enrollments()]);
  state.session = session;
  state.deployments = [];
  for (const deployment of deployments.items) {
    // Detail responses remain metadata-only and supply usage/policy for the
    // overview and configuration views without any customer event endpoint.
    state.deployments.push(await api.deployment(deployment.deployment_id));
  }
  state.enrollments = enrollments.items;
  if (state.selected) state.selected = state.deployments.find((item) => item.deployment_id === state.selected.deployment_id) || null;
  render();
}

function signInScreen(message = "Sign in with your organization identity to view deployment metadata.") {
  root.innerHTML = `<section class="auth-panel"><div class="brand-mark"><span></span></div><p class="eyebrow">Aegis Cloud Console</p><h1>Manage the fleet, keep the data local.</h1><p class="lead">${escapeHtml(message)}</p><button class="primary" id="sign-in">Continue with Logto</button></section>`;
  document.querySelector("#sign-in").addEventListener("click", async () => {
    try { location.assign(await auth.signIn(`${location.pathname}${location.hash}`)); }
    catch (error) { showError(error); }
  });
}

async function start() {
  try {
    config = readPortalConfig();
    auth = new LogtoPortalClient(config);
    api = createPortalApi({ apiBase: config.apiBase, getAccessToken: (options) => auth.getAccessToken(options) });
    if (location.pathname === "/callback") {
      const returnTo = await auth.handleCallback(location.href);
      history.replaceState({}, "", returnTo || "/");
    }
    if (!auth.hasSession()) { signInScreen(); return; }
    await loadData();
  } catch (error) {
    if (error instanceof OidcError && ["authentication_required", "invalid_grant"].includes(error.code)) {
      auth?.clear(); signInScreen(error.message); return;
    }
    root.innerHTML = `<section class="auth-panel"><p class="eyebrow">Configuration error</p><h1>The cloud console could not start.</h1><p class="lead">${escapeHtml(error.message || "Check the vendor profile configuration.")}</p></section>`;
  }
}

window.addEventListener("hashchange", () => { state.view = (location.hash || "#overview").slice(1); state.selected = null; render(); });
start();
