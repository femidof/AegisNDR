const viteEnvironment = import.meta.env ?? {};

const DEFAULT_SCOPES = [
  "openid",
  "profile",
  // Enterprise: no offline_access by default (enrollment bootstrap rejects it;
  // refresh stays bound to the Logto session).
  "urn:logto:scope:organizations",
  "urn:logto:scope:organization_roles",
  "alerts:read",
  "alerts:update",
  "events:search",
  "investigations:create",
  "investigations:read",
  "cases:create",
  "cases:update",
  "transmissions:read",
  "audit:read",
  "model-policy:manage",
];

function value(runtime, runtimeKey, environmentKey, fallback = "") {
  const configured = runtime?.[runtimeKey];
  if (configured !== undefined && configured !== null) return String(configured).trim();
  const fromEnvironment = viteEnvironment[environmentKey];
  if (fromEnvironment !== undefined && fromEnvironment !== null) return String(fromEnvironment).trim();
  return fallback;
}

function normalizeEndpoint(endpoint) {
  return endpoint.replace(/\/+$/, "");
}

function parseScopes(input) {
  if (Array.isArray(input)) return [...new Set(input.map(String).map((item) => item.trim()).filter(Boolean))];
  if (typeof input === "string" && input.trim()) {
    return [...new Set(input.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))];
  }
  return DEFAULT_SCOPES;
}

function defaultRedirectUri(location) {
  return location?.origin ? `${location.origin}/callback` : "";
}

function defaultPostLogoutUri(location) {
  return location?.origin || "";
}

function booleanValue(runtime, runtimeKey, environmentKey, fallback = false) {
  const configured = value(runtime, runtimeKey, environmentKey, fallback ? "true" : "false").toLowerCase();
  if (!new Set(["true", "false"]).has(configured)) {
    throw new Error(`${runtimeKey} must be either true or false.`);
  }
  return configured === "true";
}

function isLoopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

export function readAppConfig({ runtime = globalThis.__AEGIS_CONFIG__ ?? {}, location = globalThis.location } = {}) {
  const mode = value(runtime, "mode", "VITE_APP_MODE", "api").toLowerCase();
  if (!new Set(["api", "demo"]).has(mode)) {
    throw new Error("Application mode must be either 'api' or 'demo'.");
  }

  const config = {
    mode,
    apiBase: normalizeEndpoint(value(runtime, "apiBase", "VITE_LOCAL_API_BASE", "")),
    authMode: value(runtime, "authMode", "VITE_AUTH_MODE", mode === "demo" ? "demo" : "oidc").toLowerCase(),
    allowInsecureHttp: booleanValue(runtime, "allowInsecureHttp", "VITE_ALLOW_INSECURE_HTTP"),
    logtoEndpoint: normalizeEndpoint(value(runtime, "logtoEndpoint", "VITE_LOGTO_ENDPOINT")),
    clientId: value(runtime, "clientId", "VITE_LOGTO_CLIENT_ID"),
    resource: value(runtime, "resource", "VITE_LOGTO_RESOURCE", "https://hybrid-ndr.local/api"),
    organizationId: value(runtime, "organizationId", "VITE_LOGTO_ORGANIZATION_ID"),
    deploymentId: value(runtime, "deploymentId", "VITE_DEPLOYMENT_ID"),
    redirectUri: value(runtime, "redirectUri", "VITE_LOGTO_REDIRECT_URI", defaultRedirectUri(location)),
    postLogoutRedirectUri: value(runtime, "postLogoutRedirectUri", "VITE_LOGTO_POST_LOGOUT_URI", defaultPostLogoutUri(location)),
    scopes: parseScopes(runtime.scopes ?? viteEnvironment.VITE_LOGTO_SCOPES),
  };

  if (config.mode === "demo") {
    if (config.authMode !== "demo") throw new Error("Demo application mode requires demo authentication mode.");
    return config;
  }

  if (config.authMode !== "oidc") {
    throw new Error("API application mode requires Logto OIDC authentication.");
  }

  let browserOrigin;
  try {
    browserOrigin = new URL(location?.origin || "");
  } catch {
    throw new Error("The dashboard requires an absolute browser origin.");
  }
  if (browserOrigin.protocol !== "https:") {
    if (!config.allowInsecureHttp || browserOrigin.protocol !== "http:" || !isLoopback(browserOrigin.hostname)) {
      throw new Error("The API dashboard must be served over HTTPS. Insecure HTTP is available only for explicit loopback development.");
    }
  }
  const missing = [
    ["Logto endpoint", config.logtoEndpoint],
    ["Logto dashboard client ID", config.clientId],
    ["Logto organization ID", config.organizationId],
    ["deployment ID", config.deploymentId],
    ["OIDC redirect URI", config.redirectUri],
  ].filter(([, configured]) => !configured).map(([label]) => label);
  if (missing.length) throw new Error(`Dashboard configuration is missing: ${missing.join(", ")}.`);

  for (const [label, input] of [
    ["Logto endpoint", config.logtoEndpoint],
    ["OIDC redirect URI", config.redirectUri],
    ["post-logout redirect URI", config.postLogoutRedirectUri],
  ]) {
    let parsed;
    try {
      parsed = new URL(input);
    } catch {
      throw new Error(`${label} must be an absolute HTTP(S) URL.`);
    }
    if (!new Set(["http:", "https:"]).has(parsed.protocol)) {
      throw new Error(`${label} must be an absolute HTTP(S) URL.`);
    }
    if (parsed.protocol !== "https:" && (!config.allowInsecureHttp || !isLoopback(parsed.hostname))) {
      throw new Error(`${label} must use HTTPS outside explicit loopback development.`);
    }
    if (label !== "Logto endpoint" && parsed.origin !== browserOrigin.origin) {
      throw new Error(`${label} must use the dashboard's same origin.`);
    }
  }
  if (!config.allowInsecureHttp && config.apiBase) {
    throw new Error("The production Local API must use the dashboard's same origin.");
  }
  return config;
}

export { DEFAULT_SCOPES };
