import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { extname, join, normalize } from "node:path";

const root = "/app/dist/client";
const port = Number(process.env.PORT || 4173);
const apiTarget = new URL(process.env.API_INTERNAL_URL || "http://local-api:8080");

const types = {
  ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon", ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

function runtimeConfig() {
  const publicOrigin = String(process.env.DASHBOARD_PUBLIC_ORIGIN || "").replace(/\/$/, "");
  return {
    mode: process.env.DASHBOARD_MODE || "api",
    authMode: process.env.DASHBOARD_AUTH_MODE || "oidc",
    allowInsecureHttp: process.env.DASHBOARD_ALLOW_INSECURE_HTTP === "true",
    apiBase: "",
    logtoEndpoint: process.env.LOGTO_PUBLIC_ENDPOINT || "",
    clientId: process.env.LOGTO_DASHBOARD_CLIENT_ID || "",
    resource: process.env.AUTH_AUDIENCE || "https://hybrid-ndr.local/api",
    organizationId: process.env.LOGTO_ORGANIZATION_ID || "",
    deploymentId: process.env.DEPLOYMENT_ID || "",
    redirectUri: process.env.LOGTO_REDIRECT_URI || (publicOrigin ? `${publicOrigin}/callback` : ""),
    postLogoutRedirectUri: process.env.LOGTO_POST_LOGOUT_URI || publicOrigin,
    scopes: process.env.LOGTO_DASHBOARD_SCOPES || undefined,
  };
}

function proxyApi(incoming, outgoing) {
  const upstream = httpRequest({
    protocol: apiTarget.protocol,
    hostname: apiTarget.hostname,
    port: apiTarget.port,
    method: incoming.method,
    path: incoming.url,
    headers: { ...incoming.headers, host: apiTarget.host },
  }, (response) => {
    outgoing.writeHead(response.statusCode || 502, response.headers);
    response.pipe(outgoing);
  });
  upstream.on("error", () => {
    if (!outgoing.headersSent) outgoing.writeHead(502, { "Content-Type": "application/json" });
    outgoing.end(JSON.stringify({ error: { code: "local_api_unavailable", message: "The local API is unavailable." } }));
  });
  incoming.pipe(upstream);
}

function serveStatic(incoming, outgoing) {
  const pathname = new URL(incoming.url, "http://dashboard.local").pathname;
  const relative = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|\\|$))+/, "");
  let file = join(root, relative);
  if (!file.startsWith(root) || !existsSync(file) || statSync(file).isDirectory()) file = join(root, "index.html");
  outgoing.writeHead(200, {
    "Content-Type": types[extname(file)] || "application/octet-stream",
    "Cache-Control": file.endsWith("index.html") ? "no-store" : "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  createReadStream(file).pipe(outgoing);
}

createServer((incoming, outgoing) => {
  if (incoming.url === "/runtime-config.js") {
    outgoing.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    outgoing.end(`globalThis.__AEGIS_CONFIG__ = ${JSON.stringify(runtimeConfig())};\n`);
    return;
  }
  if (incoming.url === "/healthz") {
    outgoing.writeHead(200, { "Content-Type": "application/json" });
    outgoing.end('{"status":"healthy","service":"dashboard"}');
    return;
  }
  if (incoming.url.startsWith("/api/")) return proxyApi(incoming, outgoing);
  return serveStatic(incoming, outgoing);
}).listen(port, "0.0.0.0");
