# Local API

Run the customer-resident API with deterministic demo data:

```bash
python3 apps/local-api/app.py --host 127.0.0.1 --port 8080 --reset-demo
```

The health endpoint is `GET /healthz`. Native runs default to the explicit
`demo_headers` authentication mode. A demo analyst request uses:

```text
X-Tenant-ID: demo-tenant
X-Deployment-ID: demo-deployment
X-Actor-ID: demo-analyst
X-Role: analyst
```

The Compose profile sets `AUTH_MODE=jwt`. In that mode the API ignores actor and
role headers and requires `Authorization: Bearer <organization access token>`.
It verifies Logto's RS256 JWKS signature and validates `iss`, `aud`, `exp`,
`iat`, `jti`, `organization_id`, signed application/tenant/deployment bindings,
organization role, actor type, and product scopes. Human tokens must also carry
a Logto session ID; deployment-agent tokens must be machine tokens and cannot
combine a human role. Required configuration:

```text
AUTH_ISSUER=http://localhost:3011/oidc
AUTH_AUDIENCE=https://hybrid-ndr.local/api
AUTH_JWKS_URL=http://logto:3001/oidc/jwks
AUTH_TENANT_ID=<internal tenant id>
AUTH_DEPLOYMENT_ID=<local deployment id>
```

Access tokens are limited to 15 minutes by the Logto manifest. Logto logout or
session revocation blocks future use of the session-bound rotating refresh
token; an already-issued JWT remains valid until expiry. For an immediate local
deny, configure comma-separated `AUTH_REVOKED_TOKEN_IDS` or
`AUTH_REVOKED_SESSION_IDS` and restart the API. Each list is capped at 1,000
entries.

See `infra/logto/README.md` for the deterministic Logto bootstrap.

By default, CORS allows local previews on ports 3000, 4173, and 5173 for `localhost` and `127.0.0.1`. Override with the comma-separated `LOCAL_API_ALLOWED_ORIGINS` environment variable. With `PERSISTENCE_PROFILE=demo`, `--reset-demo` replaces only the demo tenant; immutable audit history and all other tenants are preserved. Production selects the PostgreSQL/ClickHouse/MinIO product store and rejects `--reset-demo` rather than deleting customer data.
