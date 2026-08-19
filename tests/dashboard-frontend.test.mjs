import assert from "node:assert/strict";
import test from "node:test";

import { alertStatusForApi, createDashboardApi, mapAlert, mapCase } from "../src/dashboardApi.js";
import { readAppConfig } from "../src/appConfig.js";
import { decodeJwtPayload, OidcError } from "../src/oidc.js";

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
