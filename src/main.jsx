import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import { readAppConfig } from "./appConfig.js";
import { createDashboardApi } from "./dashboardApi.js";
import { LogtoOidcClient } from "./oidc.js";
import "./styles.css";

function AuthScreen({ title, message, action, actionLabel = "Sign in with Logto", secondaryAction, secondaryLabel }) {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-mark">A</div>
        <span className="eyebrow">AEGISNDR CUSTOMER WORKSPACE</span>
        <h1>{title}</h1>
        <p>{message}</p>
        {action ? <button className="primary-button" onClick={action}>{actionLabel}</button> : <span className="auth-spinner" aria-label="Loading" />}
        {secondaryAction ? <button className="text-button" onClick={secondaryAction}>{secondaryLabel}</button> : null}
        <small>Organization-scoped access · Customer-resident security data</small>
      </section>
    </main>
  );
}

function Root() {
  const configResult = useMemo(() => {
    try {
      return { config: readAppConfig(), error: null };
    } catch (error) {
      return { config: null, error };
    }
  }, []);
  const config = configResult.config;
  const authClient = useMemo(() => config?.mode === "api" ? new LogtoOidcClient(config) : null, [config]);
  const initialized = useRef(false);
  const [authState, setAuthState] = useState(config?.mode === "demo" ? "authenticated" : "initializing");
  const [authError, setAuthError] = useState(null);
  const [user, setUser] = useState(config?.mode === "demo" ? { id: "demo-analyst", name: "Demo analyst" } : null);

  useEffect(() => {
    if (!authClient || initialized.current) return;
    initialized.current = true;
    async function initialize() {
      try {
        const url = new URL(window.location.href);
        if (url.pathname === new URL(config.redirectUri).pathname && (url.searchParams.has("code") || url.searchParams.has("error"))) {
          const returnTo = await authClient.handleCallback(url.href);
          window.history.replaceState({}, "", returnTo);
        } else if (!authClient.hasSession()) {
          setAuthState("signed-out");
          return;
        }
        await authClient.getAccessToken();
        setUser(authClient.getUser());
        setAuthState("authenticated");
      } catch (error) {
        setAuthError(error);
        setAuthState("error");
      }
    }
    initialize();
  }, [authClient, config]);

  const api = useMemo(() => {
    if (!config || config.mode !== "api" || !authClient || authState !== "authenticated") return null;
    return createDashboardApi({
      baseUrl: config.apiBase,
      deploymentId: config.deploymentId,
      getAccessToken: (options) => authClient.getAccessToken(options),
    });
  }, [authClient, authState, config]);

  if (configResult.error) {
    return <AuthScreen title="Dashboard configuration required" message={configResult.error.message} />;
  }
  if (config.mode === "demo") return <App mode="demo" user={user} />;

  async function signIn() {
    try {
      setAuthError(null);
      const target = await authClient.signIn(`${window.location.pathname}${window.location.search}`);
      window.location.assign(target);
    } catch (error) {
      setAuthError(error);
      setAuthState("error");
    }
  }

  async function signOut() {
    const target = await authClient.signOut();
    window.location.assign(target);
  }

  if (authState === "initializing") {
    return <AuthScreen title="Opening your local defense workspace" message="Validating the active organization session and obtaining a deployment-scoped API token." />;
  }
  if (authState === "signed-out") {
    return <AuthScreen title="Sign in to AegisNDR" message="Authenticate with the customer organization before accessing local alerts, evidence, cases, or audit records." action={signIn} />;
  }
  if (authState === "error") {
    return <AuthScreen title="Authentication could not be completed" message={authError?.message || "The organization session is unavailable."} action={signIn} actionLabel="Start a new sign-in" secondaryAction={() => { authClient.clear(); window.location.assign("/"); }} secondaryLabel="Clear local session" />;
  }
  return <App mode="api" api={api} user={user} onSignOut={signOut} />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
