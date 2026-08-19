import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { resolve } from "node:path";
import test from "node:test";

import { createPortalApi } from "../apps/cloud-portal/api.js";
import { readPortalConfig } from "../apps/cloud-portal/oidc.js";

test("cloud portal API uses only organization portal routes and retries one expired token", async () => {
  const requests = [];
  const refreshes = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (requests.length === 1) {
      return new Response(JSON.stringify({ error: { code: "token_expired", message: "expired" } }), {
        status: 401, headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ items: [], count: 0 }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  };
  const api = createPortalApi({
    apiBase: "/api",
    fetchImpl,
    getAccessToken: async ({ forceRefresh }) => {
      refreshes.push(forceRefresh);
      return forceRefresh ? "fresh-token" : refreshes.includes(true) ? "fresh-token" : "old-token";
    },
  });
  await api.deployments();
  assert.deepEqual(refreshes, [false, true, false]);
  assert.equal(requests[0].url, "/api/v1/portal/deployments");
  assert.equal(requests[1].options.headers.Authorization, "Bearer fresh-token");
  assert.equal(requests[1].options.credentials, "omit");
});

test("cloud portal requires explicit Logto organization configuration", () => {
  const config = readPortalConfig({
    logtoEndpoint: "https://identity.example",
    clientId: "cloud-console",
    organizationId: "org-a",
    resource: "https://hybrid-ndr.cloud/api",
    scopes: ["openid", "deployments:read"],
  }, { origin: "https://console.example" });
  assert.equal(config.redirectUri, "https://console.example/callback");
  assert.equal(config.resource, "https://hybrid-ndr.cloud/api");
  assert.throws(() => readPortalConfig({}, { origin: "https://console.example" }), /configuration is missing/i);
});

test("portal frontend has no customer analyst API route and labels its metadata boundary", async () => {
  const [application, api, markup, compose, dockerfile] = await Promise.all([
    readFile(resolve("apps/cloud-portal/app.js"), "utf8"),
    readFile(resolve("apps/cloud-portal/api.js"), "utf8"),
    readFile(resolve("apps/cloud-portal/index.html"), "utf8"),
    readFile(resolve("infra/compose/docker-compose.yml"), "utf8"),
    readFile(resolve("infra/compose/cloud-portal.Dockerfile"), "utf8"),
  ]);
  assert.match(application, /Metadata-only boundary/);
  assert.match(application, /No events/);
  assert.match(application, /No evidence/);
  assert.doesNotMatch(api, /\/api\/v1\/(alerts|events|investigations|cases|evidence)/);
  assert.match(api, /\/v1\/portal\/deployments/);
  assert.match(markup, /Aegis Cloud Console/);
  assert.match(compose, /cloud-portal:\n\s+profiles: \[vendor\]/);
  assert.match(compose, /127\.0\.0\.1:4180:4180/);
  assert.match(compose, /CONTROL_PORTAL_AUTH_AUDIENCE/);
  assert.match(dockerfile, /USER node/);
});

test("cloud portal server publishes hardened static/runtime endpoints and blocks machine APIs", async (context) => {
  const port = 43180;
  const child = spawn(process.execPath, [resolve("apps/cloud-portal/server.mjs")], {
    cwd: resolve("."),
    env: {
      ...process.env,
      PORT: String(port),
      CLOUD_PORTAL_ROOT: resolve("apps/cloud-portal"),
      LOGTO_PUBLIC_ENDPOINT: "https://identity.example",
      LOGTO_CLOUD_PORTAL_CLIENT_ID: "cloud-console",
      LOGTO_CLOUD_PORTAL_ORGANIZATION_ID: "org-a",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => child.kill("SIGTERM"));
  let health;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      health = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (health.ok) break;
    } catch { /* startup retry */ }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  assert.equal(health?.status, 200);
  assert.match(health.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  const runtime = await (await fetch(`http://127.0.0.1:${port}/runtime-config.js`)).text();
  assert.match(runtime, /https:\/\/hybrid-ndr\.cloud\/api/);
  assert.match(runtime, /cloud-console/);
  const blocked = await fetch(`http://127.0.0.1:${port}/api/v1/enrollment/exchange`, { method: "POST" });
  assert.equal(blocked.status, 404);
  assert.match(await blocked.text(), /Only cloud portal APIs/);

  // Traversal attempts are rejected before any upstream request is made,
  // whether the dots are literal, percent-encoded, or backslash-encoded.
  // fetch() normalizes dot segments client-side, so raw sockets are used to
  // deliver the exact request line an attacker would send.
  const rawRequest = (path) => new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({ hostname: "127.0.0.1", port, path, method: "GET" }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolvePromise({ status: res.statusCode, body }));
    });
    req.on("error", rejectPromise);
    req.end();
  });
  for (const attempt of [
    "/api/../../v1/portal/session",
    "/api/v1/portal/../../sensitive",
    "/api/%2e%2e/v1/portal/session",
    "/api/v1/portal/%2e%2e/session",
    "/api/v1/portal/..%5csession",
  ]) {
    const traversal = await rawRequest(attempt);
    assert.equal(traversal.status, 400, `expected 400 for ${attempt}`);
    assert.match(traversal.body, /path_traversal_rejected/);
  }
  // A prefix collision ("/api/v1/portalX") must not be treated as a portal route.
  const collision = await rawRequest("/api/v1/portalX");
  assert.equal(collision.status, 404);
  // A genuine portal route is still proxied upstream (the control API is not
  // running in this test, so the proxy reports the upstream as unavailable).
  const proxied = await rawRequest("/api/v1/portal/session");
  assert.equal(proxied.status, 502);
  assert.match(proxied.body, /control_plane_unavailable/);

  const page = await fetch(`http://127.0.0.1:${port}/deployments`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /runtime-config\.js/);
});
