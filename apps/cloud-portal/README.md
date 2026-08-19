# Aegis Cloud Console

This vendor-hosted, organization-scoped console exposes only operational
metadata: customer/account records, enrollment state, deployment and sensor
health labels, versions, aggregate usage, entitlements, model policy, updates,
and support routing. It has no route or storage contract for customer events,
evidence, packet captures, alerts, cases, or analyst notes.

The Docker Compose `vendor` profile serves the console on port `4180`. The
browser uses Logto Authorization Code + PKCE and requests an organization token
for `https://hybrid-ndr.cloud/api`. Its same-origin `/api/v1/portal/*` proxy is
intentionally unable to reach deployment mTLS or model-gateway routes.
