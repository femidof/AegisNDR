const SESSION_PREFIX = "aegis-cloud.oidc";
const TRANSACTION_MAX_AGE_MS = 10 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 30;

export class OidcError extends Error {
  constructor(message, code = "oidc_error") {
    super(message);
    this.name = "OidcError";
    this.code = code;
  }
}

function encodeBase64Url(bytes) {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomValue(cryptoProvider, size = 32) {
  const bytes = new Uint8Array(size);
  cryptoProvider.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

async function challenge(cryptoProvider, verifier) {
  if (!cryptoProvider?.subtle) throw new OidcError("Secure browser cryptography is unavailable.", "secure_context_required");
  const digest = await cryptoProvider.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return encodeBase64Url(new Uint8Array(digest));
}

export function decodeJwtPayload(token) {
  if (typeof token !== "string" || token.length > 16_384 || token.split(".").length !== 3) {
    throw new OidcError("The identity provider returned a malformed token.", "malformed_token");
  }
  try {
    const segment = token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(segment + "=".repeat((4 - segment.length % 4) % 4));
    const payload = JSON.parse(decodeURIComponent([...binary]
      .map((character) => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid payload");
    return payload;
  } catch {
    throw new OidcError("The identity provider returned a malformed token.", "malformed_token");
  }
}

function audienceIncludes(audience, expected) {
  return audience === expected || (Array.isArray(audience) && audience.includes(expected));
}

export class LogtoPortalClient {
  constructor(config, {
    fetchImpl = globalThis.fetch?.bind(globalThis),
    storage = globalThis.sessionStorage,
    cryptoProvider = globalThis.crypto,
    clock = () => Date.now(),
  } = {}) {
    if (!fetchImpl || !storage || !cryptoProvider) throw new OidcError("Required browser authentication features are unavailable.", "browser_support_required");
    this.config = config;
    this.fetch = fetchImpl;
    this.storage = storage;
    this.crypto = cryptoProvider;
    this.clock = clock;
    this.key = `${SESSION_PREFIX}:${config.clientId}:${config.organizationId}`;
    this.discovery = null;
    this.accessToken = null;
    this.accessClaims = null;
    this.refreshPromise = null;
  }

  get issuer() {
    return this.config.logtoEndpoint.endsWith("/oidc") ? this.config.logtoEndpoint : `${this.config.logtoEndpoint}/oidc`;
  }

  async getDiscovery() {
    if (this.discovery) return this.discovery;
    const response = await this.fetch(`${this.issuer}/.well-known/openid-configuration`, {
      headers: { Accept: "application/json" }, credentials: "omit",
    });
    if (!response.ok) throw new OidcError("The identity provider is unavailable.", "identity_provider_unavailable");
    const document = await response.json();
    for (const field of ["issuer", "authorization_endpoint", "token_endpoint"]) {
      if (typeof document[field] !== "string" || !document[field]) throw new OidcError("Identity discovery is incomplete.", "invalid_discovery");
    }
    if (document.issuer !== this.issuer) throw new OidcError("The configured identity issuer does not match discovery.", "issuer_mismatch");
    this.discovery = document;
    return document;
  }

  hasSession() { return Boolean(this.#read()?.refreshToken); }

  getUser() {
    const session = this.#read();
    if (!session?.idToken) return null;
    const claims = decodeJwtPayload(session.idToken);
    return {
      id: typeof claims.sub === "string" ? claims.sub : "",
      name: typeof claims.name === "string" ? claims.name : typeof claims.username === "string" ? claims.username : "Cloud administrator",
      email: typeof claims.email === "string" ? claims.email : "",
    };
  }

  async signIn(returnTo = "/") {
    const discovery = await this.getDiscovery();
    const verifier = randomValue(this.crypto, 48);
    const state = randomValue(this.crypto);
    const nonce = randomValue(this.crypto);
    this.storage.setItem(`${this.key}:transaction`, JSON.stringify({
      verifier, state, nonce,
      returnTo: returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/",
      createdAt: this.clock(),
    }));
    const query = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(" "),
      resource: this.config.resource,
      code_challenge: await challenge(this.crypto, verifier),
      code_challenge_method: "S256",
      state,
      nonce,
    });
    return `${discovery.authorization_endpoint}?${query}`;
  }

  async handleCallback(callbackUrl) {
    const url = new URL(callbackUrl);
    const raw = this.storage.getItem(`${this.key}:transaction`);
    this.storage.removeItem(`${this.key}:transaction`);
    if (!raw) throw new OidcError("The sign-in transaction is missing or already used.", "invalid_state");
    let transaction;
    try { transaction = JSON.parse(raw); } catch { throw new OidcError("The sign-in transaction is invalid.", "invalid_state"); }
    if (this.clock() - Number(transaction.createdAt) > TRANSACTION_MAX_AGE_MS || url.searchParams.get("state") !== transaction.state) {
      throw new OidcError("The sign-in response failed state validation.", "invalid_state");
    }
    if (url.searchParams.get("error")) throw new OidcError("Logto did not complete sign-in.", url.searchParams.get("error"));
    const code = url.searchParams.get("code");
    if (!code) throw new OidcError("The sign-in response did not include a code.", "missing_code");
    const discovery = await this.getDiscovery();
    const tokens = await this.#token(discovery.token_endpoint, {
      grant_type: "authorization_code", client_id: this.config.clientId, code,
      code_verifier: transaction.verifier, redirect_uri: this.config.redirectUri,
    });
    if (!tokens.refresh_token || !tokens.id_token) throw new OidcError("The identity response is incomplete.", "incomplete_token_response");
    const claims = decodeJwtPayload(tokens.id_token);
    const now = Math.floor(this.clock() / 1000);
    if (claims.iss !== this.issuer || !audienceIncludes(claims.aud, this.config.clientId) ||
        claims.nonce !== transaction.nonce || !Number.isFinite(claims.exp) || claims.exp <= now - CLOCK_SKEW_SECONDS) {
      throw new OidcError("The ID token failed validation.", "invalid_id_token");
    }
    if (!Array.isArray(claims.organizations) || !claims.organizations.includes(this.config.organizationId)) {
      throw new OidcError("This identity is not a member of the configured organization.", "organization_membership_required");
    }
    this.#write(tokens.refresh_token, tokens.id_token);
    await this.getAccessToken({ forceRefresh: true });
    return transaction.returnTo;
  }

  async getAccessToken({ forceRefresh = false } = {}) {
    if (!forceRefresh && this.accessToken && this.accessClaims && this.#fresh(this.accessClaims)) return this.accessToken;
    if (!this.refreshPromise) this.refreshPromise = this.#refresh().finally(() => { this.refreshPromise = null; });
    return this.refreshPromise;
  }

  async #refresh() {
    const session = this.#read();
    if (!session?.refreshToken) throw new OidcError("Sign-in is required.", "authentication_required");
    const discovery = await this.getDiscovery();
    let tokens;
    try {
      tokens = await this.#token(discovery.token_endpoint, {
        grant_type: "refresh_token", client_id: this.config.clientId, refresh_token: session.refreshToken,
        resource: this.config.resource, organization_id: this.config.organizationId,
        scope: this.config.scopes.join(" "),
      });
    } catch (error) {
      if (error instanceof OidcError && ["invalid_grant", "invalid_request"].includes(error.code)) this.clear();
      throw error;
    }
    if (!tokens.access_token) throw new OidcError("Logto did not return an access token.", "incomplete_token_response");
    const claims = decodeJwtPayload(tokens.access_token);
    if (!audienceIncludes(claims.aud, this.config.resource) || claims.organization_id !== this.config.organizationId || !this.#fresh(claims)) {
      throw new OidcError("The organization access token failed validation.", "invalid_access_token");
    }
    this.#write(tokens.refresh_token || session.refreshToken, tokens.id_token || session.idToken);
    this.accessToken = tokens.access_token;
    this.accessClaims = claims;
    return tokens.access_token;
  }

  async #token(endpoint, values) {
    const response = await this.fetch(endpoint, {
      method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(values), credentials: "omit",
    });
    let result = {};
    try { result = await response.json(); } catch { /* safe generic error below */ }
    if (!response.ok) throw new OidcError("Logto rejected the token request.", typeof result.error === "string" ? result.error : "token_request_failed");
    return result;
  }

  async signOut() {
    const session = this.#read();
    const discovery = await this.getDiscovery().catch(() => null);
    this.clear();
    if (!discovery?.end_session_endpoint) return this.config.postLogoutRedirectUri;
    const query = new URLSearchParams({ client_id: this.config.clientId, post_logout_redirect_uri: this.config.postLogoutRedirectUri });
    if (session?.idToken) query.set("id_token_hint", session.idToken);
    return `${discovery.end_session_endpoint}?${query}`;
  }

  clear() {
    this.accessToken = null;
    this.accessClaims = null;
    this.storage.removeItem(this.key);
    this.storage.removeItem(`${this.key}:transaction`);
  }

  #fresh(claims) { return Number.isFinite(claims.exp) && claims.exp > Math.floor(this.clock() / 1000) + CLOCK_SKEW_SECONDS; }
  #read() {
    const raw = this.storage.getItem(this.key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { this.storage.removeItem(this.key); return null; }
  }
  #write(refreshToken, idToken) { this.storage.setItem(this.key, JSON.stringify({ refreshToken, idToken })); }
}

export function readPortalConfig(runtime = globalThis.__AEGIS_CLOUD_CONFIG__ ?? {}, location = globalThis.location) {
  const scopes = Array.isArray(runtime.scopes)
    ? runtime.scopes
    : String(runtime.scopes || "").split(/[\s,]+/).filter(Boolean);
  const config = {
    apiBase: String(runtime.apiBase || "/api").replace(/\/$/, ""),
    logtoEndpoint: String(runtime.logtoEndpoint || "").replace(/\/$/, ""),
    clientId: String(runtime.clientId || ""),
    resource: String(runtime.resource || "https://hybrid-ndr.cloud/api"),
    organizationId: String(runtime.organizationId || ""),
    redirectUri: String(runtime.redirectUri || `${location.origin}/callback`),
    postLogoutRedirectUri: String(runtime.postLogoutRedirectUri || location.origin),
    scopes,
  };
  const missing = [["Logto endpoint", config.logtoEndpoint], ["cloud portal client ID", config.clientId],
    ["organization ID", config.organizationId], ["OIDC redirect URI", config.redirectUri], ["portal scopes", config.scopes.length]]
    .filter(([, value]) => !value).map(([name]) => name);
  if (missing.length) throw new Error(`Cloud portal configuration is missing: ${missing.join(", ")}.`);
  return config;
}
