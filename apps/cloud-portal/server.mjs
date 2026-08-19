import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { extname, join, normalize } from "node:path";

const root = process.env.CLOUD_PORTAL_ROOT || "/app/portal";
const port = Number(process.env.PORT || 4180);
const target = new URL(process.env.CONTROL_API_INTERNAL_URL || "http://control-api:8081");
const logtoPublicEndpoint = String(process.env.LOGTO_PUBLIC_ENDPOINT || "").replace(/\/$/, "");

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function scopes() {
  const fallback = [
    "openid", "profile", "offline_access",
    "urn:logto:scope:organizations", "urn:logto:scope:organization_roles",
    "organizations:read", "organizations:manage", "users:read", "users:manage",
    "deployments:read", "deployments:manage", "entitlements:read", "entitlements:manage",
    "policy:read", "policy:manage", "usage:read", "updates:read", "updates:manage",
    "support:read", "support:manage", "audit:read",
  ];
  const configured = String(process.env.LOGTO_CLOUD_PORTAL_SCOPES || "").split(/[\s,]+/).filter(Boolean);
  return [...new Set(configured.length ? configured : fallback)];
}

function runtimeConfig() {
  const publicOrigin = String(process.env.CLOUD_PORTAL_PUBLIC_ORIGIN || "http://localhost:4180").replace(/\/$/, "");
  return {
    apiBase: "/api",
    logtoEndpoint: logtoPublicEndpoint,
    clientId: process.env.LOGTO_CLOUD_PORTAL_CLIENT_ID || "",
    resource: process.env.CONTROL_PORTAL_AUTH_AUDIENCE || "https://hybrid-ndr.cloud/api",
    organizationId: process.env.LOGTO_CLOUD_PORTAL_ORGANIZATION_ID || "",
    redirectUri: process.env.LOGTO_CLOUD_PORTAL_REDIRECT_URI || `${publicOrigin}/callback`,
    postLogoutRedirectUri: process.env.LOGTO_CLOUD_PORTAL_POST_LOGOUT_URI || publicOrigin,
    scopes: scopes(),
  };
}

function securityHeaders(contentType = "") {
  let identityOrigin = "";
  try { identityOrigin = new URL(logtoPublicEndpoint).origin; } catch { /* invalid config is shown in the app */ }
  return {
    ...(contentType ? { "Content-Type": contentType } : {}),
    "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ${identityOrigin}; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

function proxyPortal(incoming, outgoing) {
  // Defense in depth: reject traversal on the raw request path before any URL
  // normalization. WHATWG parsing already removes literal ".." segments, but
  // percent-encoded dots and backslashes survive normalization, and upstream
  // parsers must never receive dot segments or encoded separators.
  const rawPath = String(incoming.url || "").split("?")[0];
  if (
    rawPath.split("/").includes("..")
    || /%2e/i.test(rawPath)
    || rawPath.includes("\\")
    || /%5c/i.test(rawPath)
  ) {
    outgoing.writeHead(400, { ...securityHeaders("application/json; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end('{"error":{"code":"path_traversal_rejected","message":"The proxy request path is invalid."}}');
    return;
  }
  let parsed;
  try {
    parsed = new URL(incoming.url, "http://portal.local");
  } catch {
    outgoing.writeHead(400, { ...securityHeaders("application/json; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end('{"error":{"code":"invalid_request","message":"The proxy request path is invalid."}}');
    return;
  }
  const pathname = parsed.pathname;
  const upstreamPath = pathname.slice(4) + parsed.search;
  if (!/^\/v1\/portal(?:\/|$)/.test(upstreamPath)) {
    outgoing.writeHead(404, { ...securityHeaders("application/json; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end('{"error":{"code":"route_not_found","message":"Only cloud portal APIs are exposed by this service."}}');
    return;
  }
  const forwardedHeaders = {
    accept: incoming.headers.accept || "application/json",
    authorization: incoming.headers.authorization || "",
    ...(incoming.headers["content-type"] ? { "content-type": incoming.headers["content-type"] } : {}),
    ...(incoming.headers["content-length"] ? { "content-length": incoming.headers["content-length"] } : {}),
  };
  const upstream = httpRequest({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: incoming.method,
    path: upstreamPath,
    headers: forwardedHeaders,
  }, (response) => {
    const headers = {
      ...securityHeaders(String(response.headers["content-type"] || "application/json; charset=utf-8")),
      "Cache-Control": "no-store",
    };
    outgoing.writeHead(response.statusCode || 502, headers);
    response.pipe(outgoing);
  });
  upstream.on("error", () => {
    if (!outgoing.headersSent) outgoing.writeHead(502, { ...securityHeaders("application/json; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end('{"error":{"code":"control_plane_unavailable","message":"The vendor control plane is unavailable."}}');
  });
  incoming.pipe(upstream);
}

function serveStatic(incoming, outgoing) {
  let pathname = "/";
  try { pathname = decodeURIComponent(new URL(incoming.url, "http://portal.local").pathname); } catch { /* serve application shell */ }
  const relative = normalize(pathname).replace(/^([/\\]*\.\.([/\\]|$))+/, "").replace(/^[/\\]+/, "");
  let file = join(root, relative);
  if (!file.startsWith(`${root}/`) || !existsSync(file) || statSync(file).isDirectory()) file = join(root, "index.html");
  outgoing.writeHead(200, {
    ...securityHeaders(contentTypes[extname(file)] || "application/octet-stream"),
    "Cache-Control": file.endsWith("index.html") ? "no-store" : "public, max-age=3600",
  });
  createReadStream(file).pipe(outgoing);
}

createServer((incoming, outgoing) => {
  if (incoming.url === "/healthz") {
    outgoing.writeHead(200, { ...securityHeaders("application/json; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end('{"status":"healthy","service":"cloud-portal","customer_content":"not_collected"}');
    return;
  }
  if (incoming.url === "/runtime-config.js") {
    outgoing.writeHead(200, { ...securityHeaders("text/javascript; charset=utf-8"), "Cache-Control": "no-store" });
    outgoing.end(`globalThis.__AEGIS_CLOUD_CONFIG__ = ${JSON.stringify(runtimeConfig())};\n`);
    return;
  }
  if (incoming.url?.startsWith("/api/")) return proxyPortal(incoming, outgoing);
  return serveStatic(incoming, outgoing);
}).listen(port, "0.0.0.0", () => {
  console.log(`Aegis cloud portal listening on http://0.0.0.0:${port}`);
});
