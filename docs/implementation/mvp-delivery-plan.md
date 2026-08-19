# MVP delivery plan

This plan is derived from `Hybrid AI Network Defense Platform.pdf` and
`Hybrid AI Network Defense Platform-1.pdf` in the parent workspace. A phase is
complete only when its executable acceptance evidence passes; implementation
or service health alone is not sufficient.

## Delivery loop

1. Implement the highest-risk incomplete vertical slices in parallel.
2. Integrate shared contracts, configuration, security boundaries, and Compose.
3. Run unit, integration, tenant-isolation, security, installer, UI, and
   container acceptance suites.
4. Replay the end-to-end product journey and exercise cloud/LLM outage modes.
5. Review every PDF requirement against direct runtime or test evidence.
6. Produce the next plan from all unproved requirements and repeat.

## Phase 1: make the product path real

- Replace the dashboard's implicit demo path with authenticated Local API data
  and mutations; retain demo data only behind an explicit configuration flag.
- Run Suricata and Zeek against a selected capture interface in live mode while
  keeping deterministic PCAP replay as an acceptance-test mode.
- Run detection continuously and persist alerts/evidence produced from ingested
  events without cloud availability.
- Deploy a separate, provider-independent model gateway with configurable
  zero-retention HTTP provider integration and fail-closed policy enforcement.
- Run an outbound deployment connector for health, usage, entitlements, model
  policy, update manifests, and certificate lifecycle.

### Phase 1 gate

- A signed-in analyst can search events, open/update an alert, create/retry an
  investigation, inspect its evidence/transmission, and create/update a case.
- PCAP replay and live-capture configurations both start successfully.
- Replayed traffic automatically creates expected common-schema alerts.
- Detection continues and retains alerts while vendor services are unavailable.
- A valid minimized request reaches the configured gateway/provider and an
  invalid privacy, entitlement, region, cache, certificate, or response-schema
  condition fails closed.
- Connector requests are outbound-only, authenticated, idempotent where
  required, and tolerate temporary control-plane failure.

## Phase 2: complete control and identity planes

- Implement the cloud management portal for organizations, users, deployments,
  enrollment, health, versions, entitlements, policy, usage, updates, and
  support metadata without customer event content.
- Complete automated Logto bootstrap, organization-scoped roles/permissions,
  dashboard OIDC lifecycle, deployment M2M identity, and revocation behavior.
- Replace demonstration enrollment material with CA-issued X.509 credentials,
  mTLS verification, expiry/revocation checks, and automatic rotation.
- Implement signed artifact/update manifests, customer-controlled upgrades,
  rollback, and auditable software-change records.

## Phase 3: complete analyst and administration workflows

- Back every required dashboard view with real local data: overview, traffic,
  alerts, investigations, cases/comments, log search, sensors, detection rules,
  AI transmissions, integrations, audit, and system settings.
- Add rule/suppression tuning, retention configuration, explicit evidence
  export approval, support bundles, and the specified audit coverage.
- Complete scheduled baselines, retention work, detector scheduling, metrics,
  and operational visualizations.

## Phase 4: production hardening and final acceptance

- Add private-management-network HTTPS, correct CORS/same-origin routing,
  encrypted credential-bearing service traffic, secret rotation, firewall
  guidance/automation, non-root execution, digest-pinned images, release
  signatures, and SBOM generation.
- Add OpenTelemetry and finish Grafana/Prometheus coverage for sensors,
  ingestion lag, storage, ClickHouse, and product health.
- Prove clean online/offline installation, idempotent upgrade, invalid-token and
  invalid-signature rejection, checkpoint recovery, tenant isolation, RBAC,
  certificate rejection, entitlement enforcement, and full outage behavior.

## Final MVP gate

The following journey must pass without manual database intervention:

```text
capture/replay -> Suricata + Zeek -> Vector -> ClickHouse
  -> scheduled local detection -> PostgreSQL alert + local evidence
  -> authenticated analyst investigation -> redaction/policy
  -> zero-retention gateway -> schema/evidence validation
  -> local assessment + append-only audit/transmission ledger
  -> dashboard and cloud deployment-health visibility
```

The same deployment must retain local capture, event search, detection, alerts,
cases, dashboards, and prior investigations when the control plane or model
provider is unavailable.
