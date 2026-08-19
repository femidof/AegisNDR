# Logto identity bootstrap

The checked-in manifest is the organization template for AegisNDR. It defines
the local and control API resources, their permissions, the seven organization
roles, a tenant organization, the customer dashboard SPA, the cloud portal SPA,
and the deployment-agent M2M application. Reconciliation is idempotent: an
existing object is updated by its stable name or resource indicator instead of
being duplicated.

## Local Logto OSS

The vendor profile pins Logto `1.39.0` and keeps its PostgreSQL database off the
host network. Once `logto-postgres` and `logto` are healthy, a local deployment
can be bootstrapped without Admin Console registration or a pre-created
Management API application:

```bash
export LOGTO_ENDPOINT=https://identity.vendor.example
export LOGTO_PUBLIC_ENDPOINT=https://identity.vendor.example
export DASHBOARD_PUBLIC_ORIGIN=https://ndr.customer.example
export CLOUD_PORTAL_PUBLIC_ORIGIN=https://console.vendor.example

python3 infra/logto/bootstrap.py \
  --management-endpoint http://127.0.0.1:3011 \
  --issuer https://identity.vendor.example/oidc \
  --compose-env-file infra/compose/.env \
  --output .data/logto-bootstrap-state.json
```

`LOGTO_ENDPOINT` is also Logto's canonical public endpoint and therefore must
match the TLS origin seen by browsers. `--management-endpoint` is only the
bootstrap command's transport path and may remain loopback. Non-loopback issuer,
dashboard, portal, redirect, logout, and CORS URLs must use HTTPS. The identity
origin needs a trusted certificate and must be reachable by analyst browsers;
it is deliberately separate from the customer appliance ingress.

For the pinned local schema, the command creates a 15-minute ephemeral M2M
credential directly in Logto PostgreSQL, uses the official Management API for
all product configuration, and deletes the credential even if reconciliation
fails. Its secret travels to `psql` over standard input and is never printed or
written to the bootstrap state. The direct seed refuses an unknown schema and
is not used for external or differently versioned Logto deployments.

For an external Logto deployment, provide an existing Management API token or
M2M credential and disable the local seed explicitly:

```bash
export LOGTO_MANAGEMENT_CLIENT_ID='<management application id>'
export LOGTO_MANAGEMENT_CLIENT_SECRET='<management application secret>'
python3 infra/logto/bootstrap.py \
  --no-local-management-seed \
  --management-endpoint https://identity.vendor.example \
  --issuer https://identity.vendor.example/oidc \
  --output .data/logto-bootstrap-state.json
```

Use `LOGTO_MANAGEMENT_ACCESS_TOKEN` instead when an access token is supplied by
the deployment system. Validate all rendered inputs without Logto or credentials
with `python3 infra/logto/bootstrap.py --dry-run`.

## Bootstrap output and enrollment

The mode-0600 output contains IDs, resource audiences, client-request scopes,
issuer/JWKS locations, and token-policy metadata; it contains no client secret.
Configure the control plane from these fields:

- Local enrollment: `issuer`, `jwks_uri`, `application_id`,
  `organization_id`, and `application_scopes.local_dashboard` become
  `CONTROL_IDENTITY_ISSUER`, `CONTROL_IDENTITY_JWKS_URI`,
  `LOGTO_DASHBOARD_CLIENT_ID`, `LOGTO_ORGANIZATION_ID`, and
  `LOGTO_DASHBOARD_SCOPES`.
- Cloud portal: use `control_application_id`, the same organization ID,
  `application_scopes.cloud_portal`, and the control API audience.
- Deployment agent: create or rotate a secret for
  `deployment_application_id`, keep it in a secret store, and request an
  organization client-credentials token with only `events:write sensors:write`.

The control plane includes the local dashboard identity tuple in the one-time
enrollment response. The customer installer validates the HTTPS issuer and its
matching JWKS URL, client and organization IDs, organization protocol scopes,
and the absence of `offline_access`, then writes only an allowlisted set of OIDC
values to `customer.env`. No manual customer-side OIDC edit is required.

Set `LOGTO_BOOTSTRAP_USER_ID` to an existing user ID to add the first member;
`LOGTO_BOOTSTRAP_USER_ROLE` defaults to `organization_owner`. Enterprise SAML
or OIDC connectors are configured in Logto and feed the same organization role
template.

## Token and session policy

Both API resources issue RS256 JWT access tokens with a 900-second lifetime.
Interactive tokens carry the Logto organization, application binding, tenant,
deployment assignment, role, `actor_type=human`, `jti`, and session ID. M2M
tokens carry only the deployment-agent machine role and `actor_type=machine`.
The local API validates all of those fields in addition to signature, issuer,
audience, `iat`, and `exp`, then intersects token scopes with the local role
ceiling.

Browser applications use one-day rotating refresh tokens and at most five
active grants. They intentionally omit `offline_access`; Logto still issues a
session-bound refresh token, so sign-out or session/grant revocation prevents
future refresh. Already-issued self-contained JWTs remain valid until their
900-second expiry. `AUTH_REVOKED_TOKEN_IDS` and `AUTH_REVOKED_SESSION_IDS` are
bounded emergency deny lists for immediate local rejection while a service is
restarted with updated configuration.

Official references:

- [Self-host Logto](https://docs.logto.io/logto-oss/deployment-and-configuration)
- [Interact with the Management API](https://docs.logto.io/integrate-logto/interact-with-management-api)
- [Organization-level API resources](https://docs.logto.io/authorization/organization-level-api-resources)
- [Custom token claims](https://docs.logto.io/developers/custom-token-claims/create-script)
- [Sign-out and session management](https://docs.logto.io/end-user-flows/sign-out)
