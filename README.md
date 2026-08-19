# AegisNDR — Hybrid AI Network Defense Platform

A runnable MVP of a customer-resident Network Detection and Response platform with a vendor-hosted control plane. The implementation follows the two product specifications in the parent workspace and demonstrates the primary product promise:

> Install locally, manage centrally, keep security data under customer control.

## What works

- Analyst dashboard with traffic, alerts, investigations, evidence citations, cases, sensors, AI transmissions, audit, and system settings.
- Local detection for port scans, DNS-volume/tunneling signals, traffic spikes, new destinations, and Suricata alert conversion.
- Local evidence collection, redaction, minimized evidence packaging, structured assessment validation, and an inspectable transmission ledger.
- Offline-safe investigations: detection and local findings continue when the model gateway is unavailable.
- Tenant-scoped local APIs and role/permission enforcement for analyst, auditor, administrator, read-only, and deployment-agent roles.
- Self-hosted Logto with organization RBAC, deterministic manifest/bootstrap, strict JWT/JWKS validation, and an isolated identity database.
- Control-plane enrollment, single-use enrollment tokens, heartbeat, entitlements, model policy, and metadata-only usage metering.
- Vendor cloud console with Logto organization authentication, customer and deployment enrollment, fleet health/version/sensor status, aggregate usage, entitlements, policy, updates, and support metadata—without customer event or evidence access.
- Single-node Docker Compose topology for the application plus Suricata, Zeek, Vector, ClickHouse, PostgreSQL, MinIO, Logto, Grafana, and Prometheus.
- Deterministic demo fixtures and automated unit, integration, security, and tenant-isolation tests.

## Quick start

### Local product UI

Node.js 22.14.0 or newer is required. If Node is not installed, install it
with your operating system package manager or [nvm](https://github.com/nvm-sh/nvm),
then run the repository setup check:

```bash
./scripts/setup-node.sh
```

```bash
npm install
npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

The UI includes a complete demo journey and gracefully uses seeded local data when the API is unavailable.

### Local API and control plane

The backend uses the Python standard library so the demo can run without downloading Python dependencies.

```bash
python3 apps/local-api/app.py --host 127.0.0.1 --port 8080 --reset-demo
python3 apps/control-api/app.py --host 127.0.0.1 --port 8081 --reset-demo
```

### Automated verification

```bash
npm run build
npm run test:sites
python3 -m unittest discover -s tests -p 'test_*.py'
```

### Full single-node topology

For explicit local HTTP development, start the customer-resident data plane
with the base Compose file:

```bash
docker compose -f infra/compose/docker-compose.yml \
  --env-file infra/compose/.env.example \
  --profile customer up -d --build
```

That base-only path explicitly enables development HTTP and publishes ports
`4173`, `8080`, and `3001`; keep it on loopback or an isolated test network.
Production installation always adds `docker-compose.https.yml`, removes those
ports, and exposes a host-locked TLS origin on ports 80/443 with the dashboard
at `/`, Local API at `/api/`, and Grafana at `/grafana/`. The installer can
generate an exact-SAN private-LAN certificate or validate supplied enterprise
material. Databases and object storage remain private. See
[`docs/deployment/private-lan-https.md`](docs/deployment/private-lan-https.md).

The vendor-hosted identity and control services are isolated in a separate
profile:

```bash
docker compose -f infra/compose/docker-compose.yml \
  --env-file infra/compose/.env.example \
  --profile vendor up -d --build
```

Logto is then published on local ports `3011` (OIDC) and `3012` (Admin Console).
The organization-scoped cloud console is published on `4180`, and its
same-origin proxy can reach only human `/v1/portal/*` APIs. The control API and
standalone model gateway remain on `8081` and `8082` for the development
profile.
After its first start, complete the one-time Management API registration and
identity bootstrap documented in `infra/logto/README.md`.

## Repository map

```text
apps/                 Local and control-plane APIs
apps/cloud-portal/    Vendor metadata-only management console
services/             Detection, agent, model-gateway, and ingestion logic
packages/             Shared contracts, redaction, auth, and audit helpers
src/                  Customer-resident analyst dashboard
infra/                Compose and service configuration
installer/            Preflight, install, and verification scripts
tests/                 Unit, integration, security, and isolation tests
docs/                  Architecture, threat model, API, and demo guidance
```

## Security boundary

Raw events, packet captures, internal identifiers, alert evidence, cases, analyst notes, credentials, and audit records remain in the customer environment. Only a policy-approved minimized evidence package can cross the outbound model boundary. The gateway stores usage metadata—not prompts, responses, or evidence—and fails closed when zero-retention or regional policy cannot be verified.

This MVP does not perform autonomous blocking or endpoint isolation.

## Customer appliance installation

Use the signed, customer-only installer workflow in
[`docs/deployment/customer-installer.md`](docs/deployment/customer-installer.md).
It covers online and offline bundles, checksum/signature verification before
privilege, single-use enrollment, local P-256 identity, idempotent upgrades,
post-install health checks, and data-preserving uninstall. The installer never
deploys vendor Logto or the vendor control API on the customer device.
