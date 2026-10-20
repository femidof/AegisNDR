import assert from "node:assert/strict";
import test from "node:test";

import { alertStatusForApi, createDashboardApi, mapAlert, mapCase, mapEvent } from "../src/dashboardApi.js";
import { readAppConfig } from "../src/appConfig.js";
import { decodeJwtPayload, OidcError } from "../src/oidc.js";
import { loadDashboard, trustStatus } from "../src/dashboardState.js";
import { createRequire } from "node:module";
import { resolve } from "node:path";

test("dashboard maps local API identifiers and statuses without demo-shaped assumptions", () => {
  const alert = mapAlert({
    alert_id: "alert-123", title: "Port scan", severity: "high", status: "investigating",
    detector_id: "port_scan", entity_id: "10.0.0.8", score: 0.91, evidence_ids: ["event-1"],
    created_at: "2026-08-05T12:00:00Z",
  });
  assert.equal(alert.id, "alert-123");
  assert.equal(alert.status, "Under Investigation");
  assert.deepEqual(alert.evidenceIds, ["event-1"]);
  assert.equal(alertStatusForApi("Acknowledged"), "triaged");

  const incident = mapCase({
    case_id: "case-123", alert_ids: ["alert-123"], title: "Investigate scan",
    priority: "critical", status: "in_progress", assignee: "Analyst", updated_at: "2026-08-05T12:00:00Z",
  });
  assert.equal(incident.id, "case-123");
  assert.equal(incident.alertId, "alert-123");
  assert.equal(incident.priority, "P1");
  assert.equal(incident.status, "In progress");
});

test("dashboard API unwraps {items,count}, attaches bearer/deployment headers, and retries one 401", async () => {
  const requests = [];
  const tokenCalls = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (requests.length === 1) return new Response(JSON.stringify({ error: { code: "expired", message: "expired" } }), { status: 401, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ items: [{
      alert_id: "alert-1", title: "DNS anomaly", severity: "medium", status: "open",
      detector_id: "dns_tunnel", entity_id: "host-1", score: 0.7, created_at: "2026-08-05T12:00:00Z",
    }], count: 1 }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const api = createDashboardApi({
    deploymentId: "deployment-1", fetchImpl,
    getAccessToken: async ({ forceRefresh }) => { tokenCalls.push(forceRefresh); return forceRefresh ? "fresh-token" : tokenCalls.includes(true) ? "fresh-token" : "old-token"; },
  });
  const alerts = await api.listAlerts();
  assert.equal(alerts[0].id, "alert-1");
  assert.deepEqual(tokenCalls, [false, true, false]);
  assert.equal(requests[1].options.headers.Authorization, "Bearer fresh-token");
  assert.equal(requests[1].options.headers["X-Deployment-ID"], "deployment-1");
});

test("production config is explicit, complete, and same-origin capable", () => {
  const config = readAppConfig({
    runtime: {
      mode: "api", authMode: "oidc", apiBase: "", logtoEndpoint: "https://identity.lan",
      clientId: "dashboard", organizationId: "org-1", deploymentId: "deployment-1",
    },
    location: { origin: "https://ndr.lan" },
  });
  assert.equal(config.apiBase, "");
  assert.equal(config.redirectUri, "https://ndr.lan/callback");
  assert.throws(() => readAppConfig({ runtime: { mode: "api" }, location: { origin: "https://ndr.lan" } }), /configuration is missing/i);
});

test("production API mode requires HTTPS and same-origin callbacks", () => {
  const complete = {
    mode: "api", authMode: "oidc", apiBase: "", logtoEndpoint: "https://identity.lan",
    clientId: "dashboard", organizationId: "org-1", deploymentId: "deployment-1",
  };
  assert.throws(
    () => readAppConfig({ runtime: complete, location: { origin: "http://192.168.1.50" } }),
    /must be served over HTTPS/i,
  );
  assert.throws(
    () => readAppConfig({
      runtime: { ...complete, redirectUri: "https://other.lan/callback" },
      location: { origin: "https://ndr.lan" },
    }),
    /same origin/i,
  );
});

test("HTTP API mode is restricted to an explicit loopback development switch", () => {
  const config = readAppConfig({
    runtime: {
      mode: "api", authMode: "oidc", allowInsecureHttp: true, apiBase: "http://127.0.0.1:8080",
      logtoEndpoint: "http://localhost:3011", clientId: "dashboard", organizationId: "org-1",
      deploymentId: "deployment-1", redirectUri: "http://localhost:4173/callback",
      postLogoutRedirectUri: "http://localhost:4173",
    },
    location: { origin: "http://localhost:4173" },
  });
  assert.equal(config.allowInsecureHttp, true);
  assert.throws(
    () => readAppConfig({
      runtime: { ...config, redirectUri: "http://192.168.1.50/callback" },
      location: { origin: "http://192.168.1.50" },
    }),
    /only for explicit loopback development/i,
  );
});

test("JWT parsing rejects opaque and malformed identity tokens", () => {
  assert.throws(() => decodeJwtPayload("opaque-token"), OidcError);
  assert.throws(() => decodeJwtPayload("a.invalid.c"), OidcError);
});

function fixtureApi() {
  const values = {
    getOverview: { events: 1 }, listAlerts: [{ id: "alert-1" }], listCases: [], listSensors: [],
    searchEvents: [], listTransmissions: [], listAudit: { events: [], chainValid: true },
    getModelPolicy: { enabled: false, level: "strict" }, listInvestigations: [],
    getSession: { actor_id: "analyst", permissions: ["alerts:read"] }, listDetectionRules: [],
    listSuppressions: [], listIntegrations: [], getSystemSettings: {}, listEvidenceExports: [], listSupportBundles: [],
  };
  return Object.fromEntries(Object.entries(values).map(([method, value]) => [method, async () => structuredClone(value)]));
}

test("permission denial in an optional view does not hide authorized alert data", async () => {
  const api = fixtureApi();
  api.listAudit = async () => { throw Object.assign(new Error("Permission denied"), { status: 403 }); };
  const result = await loadDashboard(api);
  assert.deepEqual(result.alerts, [{ id: "alert-1" }]);
  assert.equal(result.dataSource, "backend");
  assert.equal(result.errors.audit.status, 403);
  assert.deepEqual(result.audit.events, []);
  assert.equal(result.policy.enabled, false);
});

test("API outages return explicit unavailable data with no demo fallback", async () => {
  const api = Object.fromEntries(Object.keys(fixtureApi()).map((method) => [method, async () => { throw new Error("Unavailable"); }]));
  const result = await loadDashboard(api);
  assert.equal(result.dataSource, "error");
  assert.deepEqual(result.alerts, []);
  assert.equal(result.policy, null);
  assert.equal(result.rules, null);
  assert.equal(result.session, null);
});

test("health badges require fresh evidence and never claim live demo health", () => {
  const source = { demoMode: false, dataSource: "backend", health: { status: "healthy" }, observedAt: 99_000, policy: { enabled: false } };
  assert.equal(trustStatus(source, 100_000).healthy, true);
  assert.equal(trustStatus(source, 100_000).policy, "Disabled");
  assert.equal(trustStatus(source, 129_000).healthy, false);
  assert.equal(trustStatus(source, 98_000).healthy, false);
  assert.equal(trustStatus({ ...source, dataSource: "error", health: null, policy: null }, 100_000).data, "Unavailable");
  assert.equal(trustStatus({ ...source, demoMode: true }, 100_000).healthy, false);
  assert.equal(trustStatus({ ...source, demoMode: true }, 100_000).node, "Preview");
});

test("session and bounded health reads use the authenticated customer API routes", async () => {
  const requests = [];
  const api = createDashboardApi({ deploymentId: "deployment-1", getAccessToken: async () => "token",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return new Response(JSON.stringify({ status: "healthy" }), { status: 200 });
    } });
  await api.getSession();
  await api.getSystemHealth();
  assert.equal(requests[0].url, "/api/v1/session");
  assert.ok(requests[0].options.signal instanceof AbortSignal);
  assert.equal(requests[1].url, "/api/v1/system/health");
  assert.equal(requests[1].options.headers["X-Deployment-ID"], "deployment-1");
  assert.ok(requests[1].options.signal instanceof AbortSignal);
});

let renderedComponents;
async function components() {
  if (!renderedComponents) {
    renderedComponents = import("esbuild").then(async ({ build }) => {
      const output = await build({ stdin: { contents: `
        export { App } from "./src/App.jsx";
        export { SettingsPage } from "./src/pages/SettingsPage.jsx";
        export { DetectionRulesPage } from "./src/pages/DetectionRulesPage.jsx";
        export { IntegrationsPage } from "./src/pages/IntegrationsPage.jsx";
        export { TrafficPage } from "./src/pages/TrafficPage.jsx";
      `, resolveDir: resolve("."), loader: "jsx" }, bundle: true, platform: "node", format: "cjs",
        external: ["react", "react/*", "react-dom", "react-dom/*"], mainFields: ["module", "main"], jsx: "automatic", write: false });
      const compiled = { exports: {} };
      new Function("require", "module", "exports", output.outputFiles[0].text)(createRequire(import.meta.url), compiled, compiled.exports);
      return compiled.exports;
    });
  }
  return renderedComponents;
}

test("production shell and default settings render without fake status or missing-prop crashes", async () => {
  const { createElement } = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { App, SettingsPage } = await components();
  const shell = renderToStaticMarkup(createElement(App, { mode: "api", api: fixtureApi() }));
  assert.match(shell, /Health unavailable/);
  assert.match(shell, /Policy: Unavailable/);
  assert.doesNotMatch(shell, /LLM STATUS|Enforce|Explicit Demo|DNS Tunneling Detected/);
  const settings = renderToStaticMarkup(createElement(SettingsPage, { demoMode: false }));
  assert.match(settings, /Policy unavailable/);
  assert.match(settings, /disabled=""/);
  assert.doesNotMatch(settings, /Zero-retention verified/);
});

test("read-only administration pages render their records with mutation controls disabled", async () => {
  const { createElement } = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { DetectionRulesPage, IntegrationsPage } = await components();
  const rules = renderToStaticMarkup(createElement(DetectionRulesPage, { canManage: false,
    rules: [{ rule_id: "rule-1", name: "Local rule", enabled: true, builtin: true }], suppressions: [] }));
  assert.match(rules, /Local rule/);
  assert.match(rules, /disabled=""/);
  const integrations = renderToStaticMarkup(createElement(IntegrationsPage, { canManage: false, integrations: [] }));
  assert.match(integrations, /disabled=""/);
});


test("traffic chart uses actual event timestamps and bounded sample groups", async () => {
  const { trafficSeries, trafficGroups } = await import("../src/trafficData.js");
  const now = Date.parse("2026-10-20T22:00:00Z");
  const rows = [0, 4000, 5000, 59000, 60000, -1000].map((age) => ({ eventTime: new Date(now - age).toISOString(), protocolValue: "tcp" }));
  rows.push({ eventTime: "invalid", protocolValue: "udp" });
  const buckets = trafficSeries(rows, now);
  assert.equal(buckets.length, 12);
  assert.equal(buckets[11], 2);
  assert.equal(buckets[10], 1);
  assert.equal(buckets[0], 1);
  assert.equal(buckets.reduce((sum, value) => sum + value, 0), 4);
  assert.deepEqual(trafficGroups(rows, "protocolValue"), [["tcp", 6], ["udp", 1]]);
  assert.deepEqual(trafficGroups([{ protocol: "DNS/TXT" }], "protocolValue"), [["DNS", 1]]);
});

test("traffic view renders a truthful waiting state and sample charts", async () => {
  const { createElement } = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { TrafficPage } = await components();
  const waiting = renderToStaticMarkup(createElement(TrafficPage, {}));
  assert.match(waiting, /Waiting for the local API/);
  assert.match(waiting, /not packets per second/);
  assert.doesNotMatch(waiting, /Live local index|>Allowed</);
  const preview = renderToStaticMarkup(createElement(TrafficPage, { demoMode: true, rows: [mapEvent({ event_id: "e1", event_time: new Date().toISOString(), source: "zeek", protocol: "tcp", src_ip: "10.0.0.1", dst_ip: "10.0.0.2" })] }));
  assert.match(preview, /Preview/);
  assert.match(preview, /role="img"/);
  assert.match(preview, /Observed/);
  assert.match(preview, /10.0.0.2/);
});

test("dashboard permits only its configured identity origin and forwards deployment scope", async () => {
  const { spawn } = await import("node:child_process");
  const { createServer } = await import("node:net");
  const { once } = await import("node:events");
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const child = spawn(process.execPath, ["infra/compose/dashboard-server.mjs"], { env: { ...process.env, PORT: String(port), LOGTO_PUBLIC_ENDPOINT: "http://localhost:3011" }, stdio: "ignore" });
  try {
    let response;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try { response = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(500) }); break; }
      catch { await new Promise((resolve) => setTimeout(resolve, 25)); }
    }
    assert.ok(response, "dashboard did not start");
    const csp = response.headers.get("content-security-policy");
    assert.match(csp, /connect-src 'self' http:\/\/localhost:3011;/);
    assert.doesNotMatch(csp, /connect-src[^;]*\*/);
    assert.equal(response.status, 200);
  } finally {
    child.kill();
    if (child.exitCode === null) await once(child, "exit");
  }
});
