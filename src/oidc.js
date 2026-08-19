const SESSION_KEY_PREFIX = "aegis-ndr.oidc";
const AUTHORIZATION_MAX_AGE_MS = 10 * 60 * 1000;
const TOKEN_CLOCK_SKEW_SECONDS = 30;

export class OidcError extends Error {
  constructor(message, code = "oidc_error") {
    super(message);
    this.name = "OidcError";
    this.code = code;
  }
}

function base64Url(bytes) {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomValue(cryptoProvider, byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  cryptoProvider.getRandomValues(bytes);
  return base64Url(bytes);
}

async function pkceChallenge(cryptoProvider, verifier) {
  if (!cryptoProvider?.subtle) {
    // WebCrypto is only available in secure contexts (HTTPS or localhost).
    // The message is user-facing, so it explains the fix without leaking
    // deployment configuration details.
    throw new OidcError(
      "This browser cannot provide the secure cryptography required for sign-in. Open this console over HTTPS, or contact your administrator if it is already HTTPS.",
      "secure_context_required",
    );
  }
  const digest = await cryptoProvider.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
}

export function decodeJwtPayload(token) {
  if (typeof token !== "string" || token.length > 16_384) throw new OidcError("The identity provider returned a malformed token.", "malformed_token");
  const parts = token.split(".");
  if (parts.length !== 3) throw new OidcError("The identity provider did not return the required JWT.", "jwt_required");
  try {
    const payload = JSON.parse(decodeURIComponent([...decodeBase64Url(parts[1])]
      .map((character) => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid payload");
    return payload;
  } catch {
    throw new OidcError("The identity provider returned a malformed JWT.", "malformed_token");
  }
}

function audienceIncludes(audience, expected) {
  return audience === expected || (Array.isArray(audience) && audience.includes(expected));
}

function storageKey(config) {
  return `${SESSION_KEY_PREFIX}:${config.clientId}:${config.organizationId}`;
}

export class LogtoOidcClient {
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
    this.key = storageKey(config);
    this.discovery = null;
    this.accessToken = null;
    this.accessClaims = null;
    this.refreshPromise = null;
  }

  get issuer() {
    return this.config.logtoEndpoint.endsWith("/oidc")
      ? this.config.logtoEndpoint
      : `${this.config.logtoEndpoint}/oidc`;
  }

  async getDiscovery() {
    if (this.discovery) return this.discovery;
    const response = await this.fetch(`${this.issuer}/.well-known/openid-configuration`, {
      headers: { Accept: "application/json" },
      credentials: "omit",
    });
    if (!response.ok) throw new OidcError("The Logto discovery document is unavailable.", "identity_provider_unavailable");
    const discovery = await response.json();
    for (const field of ["issuer", "authorization_endpoint", "token_endpoint"]) {
      if (typeof discovery[field] !== "string" || !discovery[field]) {
        throw new OidcError("The Logto discovery document is incomplete.", "invalid_discovery");
      }
    }
    if (discovery.issuer !== this.issuer) {
      throw new OidcError("The Logto issuer does not match the configured identity provider.", "issuer_mismatch");
    }
    this.discovery = discovery;
    return discovery;
  }

  hasSession() {
    return Boolean(this.#readSession()?.refreshToken);
  }

  getUser() {
    const session = this.#readSession();
    if (!session?.idToken) return null;
    const claims = decodeJwtPayload(session.idToken);
    return {
      id: typeof claims.sub === "string" ? claims.sub : "",
      name: typeof claims.name === "string" ? claims.name : typeof claims.username === "string" ? claims.username : "Signed-in analyst",
      email: typeof claims.email === "string" ? claims.email : "",
      claims,
    };
  }

  async signIn(returnTo = "/") {
    const discovery = await this.getDiscovery();
    const verifier = randomValue(this.crypto, 48);
    const state = randomValue(this.crypto);
    const nonce = randomValue(this.crypto);
    const challenge = await pkceChallenge(this.crypto, verifier);
    this.storage.setItem(`${this.key}:transaction`, JSON.stringify({
      verifier,
      state,
      nonce,
      returnTo: returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/",
      createdAt: this.clock(),
    }));
    const parameters = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(" "),
      resource: this.config.resource,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });
    return `${discovery.authorization_endpoint}?${parameters}`;
  }

  async handleCallback(callbackUrl) {
    const url = new URL(callbackUrl);
    const transactionRaw = this.storage.getItem(`${this.key}:transaction`);
    this.storage.removeItem(`${this.key}:transaction`);
    if (!transactionRaw) throw new OidcError("The sign-in transaction is missing or has already been used.", "invalid_state");
    let transaction;
    try {
      transaction = JSON.parse(transactionRaw);
    } catch {
      throw new OidcError("The sign-in transaction is invalid.", "invalid_state");
    }
    if (this.clock() - Number(transaction.createdAt) > AUTHORIZATION_MAX_AGE_MS) {
      throw new OidcError("The sign-in transaction expired. Please sign in again.", "invalid_state");
    }
    if (!url.searchParams.get("state") || url.searchParams.get("state") !== transaction.state) {
      throw new OidcError("The sign-in response failed state validation.", "invalid_state");
    }
    const providerError = url.searchParams.get("error");
    if (providerError) throw new OidcError("Logto did not complete sign-in.", providerError);
    const code = url.searchParams.get("code");
    if (!code) throw new OidcError("The sign-in response did not contain an authorization code.", "missing_code");

    const discovery = await this.getDiscovery();
    const tokens = await this.#tokenRequest(discovery.token_endpoint, {
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      code_verifier: transaction.verifier,
      redirect_uri: this.config.redirectUri,
    });
    if (!tokens.refresh_token || !tokens.id_token) {
      throw new OidcError("Logto did not return the refresh and ID tokens required for organization access.", "incomplete_token_response");
    }
    const idClaims = decodeJwtPayload(tokens.id_token);
    this.#validateIdClaims(idClaims, transaction.nonce);
    const organizations = Array.isArray(idClaims.organizations) ? idClaims.organizations : [];
    if (!organizations.includes(this.config.organizationId)) {
      throw new OidcError("This identity is not a member of the configured customer organization.", "organization_membership_required");
    }
    this.#writeSession({ refreshToken: tokens.refresh_token, idToken: tokens.id_token });
    await this.getAccessToken({ forceRefresh: true });
    return transaction.returnTo;
  }

  async getAccessToken({ forceRefresh = false } = {}) {
    if (!forceRefresh && this.accessToken && this.accessClaims && this.#isFresh(this.accessClaims)) return this.accessToken;
    if (!this.refreshPromise) {
      this.refreshPromise = this.#refreshOrganizationToken().finally(() => {
        this.refreshPromise = null;
      });
    }
    return this.refreshPromise;
  }

  async signOut() {
    const session = this.#readSession();
    const discovery = await this.getDiscovery().catch(() => null);
    this.clear();
    if (!discovery?.end_session_endpoint) return this.config.postLogoutRedirectUri;
    const parameters = new URLSearchParams({
      client_id: this.config.clientId,
      post_logout_redirect_uri: this.config.postLogoutRedirectUri,
    });
    if (session?.idToken) parameters.set("id_token_hint", session.idToken);
    return `${discovery.end_session_endpoint}?${parameters}`;
  }

  clear() {
    this.accessToken = null;
    this.accessClaims = null;
    this.storage.removeItem(this.key);
    this.storage.removeItem(`${this.key}:transaction`);
  }

  async #refreshOrganizationToken() {
    const session = this.#readSession();
    if (!session?.refreshToken) throw new OidcError("Sign-in is required.", "authentication_required");
    const discovery = await this.getDiscovery();
    let tokens;
    try {
      tokens = await this.#tokenRequest(discovery.token_endpoint, {
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        refresh_token: session.refreshToken,
        resource: this.config.resource,
        organization_id: this.config.organizationId,
        scope: this.config.scopes.join(" "),
      });
    } catch (error) {
      if (error instanceof OidcError && new Set(["invalid_grant", "invalid_request"]).has(error.code)) this.clear();
      throw error;
    }
    if (!tokens.access_token) throw new OidcError("Logto did not return an organization access token.", "incomplete_token_response");
    const claims = decodeJwtPayload(tokens.access_token);
    this.#validateAccessClaims(claims);
    this.#writeSession({
      refreshToken: tokens.refresh_token || session.refreshToken,
      idToken: tokens.id_token || session.idToken,
    });
    this.accessToken = tokens.access_token;
    this.accessClaims = claims;
    return this.accessToken;
  }

  async #tokenRequest(endpoint, values) {
    const response = await this.fetch(endpoint, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(values),
      credentials: "omit",
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      // The error below intentionally avoids reflecting an identity-provider body.
    }
    if (!response.ok) {
      const code = typeof payload.error === "string" ? payload.error : "token_request_failed";
      throw new OidcError("Logto rejected the token request.", code);
    }
    return payload;
  }

  #validateIdClaims(claims, nonce) {
    const now = Math.floor(this.clock() / 1000);
    if (claims.iss !== this.issuer || !audienceIncludes(claims.aud, this.config.clientId)) {
      throw new OidcError("The ID token issuer or audience is invalid.", "invalid_id_token");
    }
    if (claims.nonce !== nonce || !Number.isFinite(claims.exp) || claims.exp <= now - TOKEN_CLOCK_SKEW_SECONDS) {
      throw new OidcError("The ID token failed nonce or expiration validation.", "invalid_id_token");
    }
  }

  #validateAccessClaims(claims) {
    if (!audienceIncludes(claims.aud, this.config.resource)) {
      throw new OidcError("Logto returned a token for the wrong API resource.", "invalid_access_token_audience");
    }
    if (claims.organization_id !== this.config.organizationId) {
      throw new OidcError("Logto returned a token for the wrong organization.", "invalid_access_token_organization");
    }
    const deployments = Array.isArray(claims.deployment_ids) ? claims.deployment_ids : [];
    if (!deployments.includes(this.config.deploymentId)) {
      throw new OidcError("The organization token is not assigned to this deployment.", "invalid_access_token_deployment");
    }
    if (!this.#isFresh(claims)) throw new OidcError("Logto returned an expired access token.", "token_expired");
  }

  #isFresh(claims) {
    return Number.isFinite(claims.exp) && claims.exp > Math.floor(this.clock() / 1000) + TOKEN_CLOCK_SKEW_SECONDS;
  }

  #readSession() {
    const raw = this.storage.getItem(this.key);
    if (!raw) return null;
    try {
      const value = JSON.parse(raw);
      return value && typeof value === "object" ? value : null;
    } catch {
      this.storage.removeItem(this.key);
      return null;
    }
  }

  #writeSession({ refreshToken, idToken }) {
    this.storage.setItem(this.key, JSON.stringify({ refreshToken, idToken }));
  }
}
