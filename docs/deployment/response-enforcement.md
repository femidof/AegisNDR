# Deploy response enforcement

Response is optional and defaults to off. This guide describes the implemented
paths, their configuration, and their operational limits. It does not report lab
acceptance or authorize containment on an existing deployment.

## Supported implementations

| Adapter type | Operation | Enforcement location | Verification |
|---|---|---|---|
| `nftables_gateway` | Address block in both directions on a named forwarding interface | Linux gateway through which the traffic actually passes | Read back the action-owned nftables table, rules and timed address element |
| `linux_endpoint` | Isolate a Linux device except explicit management networks, loopback and IPv6 neighbour/router discovery | Native service on that Linux endpoint | Read back the exact action-owned input/output/forward rules and verify their removal on release |
| `defender` | Full or selective isolation, and release, for Windows 10/11 devices | Microsoft Defender for Endpoint | Correlate asynchronous machine actions and independently probe fixed canary paths over a preserved mTLS management channel |

These are concrete adapters, not a promise of arbitrary firewall/EDR brands or
native Windows/macOS agent support. The passive NDR sensor is not an inline
enforcement point. Gateway deployment checks forwarding and interface presence;
the operator must route the intended traffic through that interface. Native
endpoint isolation is an IP-layer restriction; it does not disable the NIC or
claim to filter every non-IP Ethernet protocol.

## 1. Provision the enforcement service

For native gateway/endpoint enforcement, install Python 3.12+, nftables and
iproute2 on the target Linux host. Place this repository at `/opt/aegisndr`, owned
by the administrator and not writable by the service's network callers. Use
`infra/response/gateway.example.json` or `endpoint.example.json` as the starting
configuration; replace all example identities, addresses and zero fingerprints.

The configuration binds a deployment, integration ID, stable target IDs, exact
addresses, management exceptions and permitted controller certificate fingerprints.
The endpoint service also checks that the requested address is currently assigned
locally. Addresses shared by multiple targets are rejected.

Issue a dedicated controller client certificate and a server certificate for
each enforcement/probe host using a trusted CA. Include the correct server DNS/IP
SAN and appropriate client/server EKU. Trust the CA and pin the exact controller
client certificate fingerprint, rather than accepting arbitrary deployment
clients. Obtain the fingerprint from the actual client certificate:

```bash
openssl x509 -in controller-cert.pem -outform DER | openssl dgst -sha256
```

Store the service configuration and TLS files under `/etc/aegisndr-response/`.
Keep private keys owner-readable only. Before installation, print the nonsecret
configuration revision without applying any network rules:

```bash
cd /opt/aegisndr
python3 services/response-enforcer/app.py \
  --config /etc/aegisndr-response/enforcer.json --print-revision
```

Copy the supplied `infra/response/aegisndr-response-enforcer.service` to the
systemd unit directory and enable it after reviewing its paths and management
exceptions. It runs with `CAP_NET_ADMIN`, a protected filesystem, and its own
durable state directory. The worker and Local API do not receive this capability.
Do not run the enforcer in an unrelated container network namespace: its nftables
changes affect the network namespace where the service executes.

The TLS listener defaults to loopback in the CLI; the unit binds port 9443 on the
host. Restrict that port to the controller management path in the host's existing
firewall. TLS validates the peer certificate and the application pins its
fingerprint. Caller headers cannot substitute for a verified peer certificate.

The service accepts only bounded typed prepare/apply/observe/release operations.
It does not accept shell text, SQL, URLs or arbitrary nftables programs. Each
operation is bound to a durable action ID and proposal hash. New commands must
arrive within their authorization window. Reusing an action ID with changed
content is rejected; an identical replay does not reapply a released action.

## 2. Configure the customer worker

Copy `infra/response/controller.example.json` to a customer-owned configuration
file. Replace its tenant/deployment with the installed deployment IDs. Start
with `enabled: false` and `automatic_proposals: false`.

Add an integration record for each native enforcer. For example:

```json
{
  "id": "lab-gateway",
  "type": "nftables_gateway",
  "endpoint": "https://gateway.customer.example:9443",
  "platforms": ["linux", "Windows10", "Windows11"],
  "targets": {"lab-endpoint-01": ["192.0.2.10"]},
  "ca_file": "/run/response-secrets/gateway-ca.pem",
  "certificate_file": "/run/response-secrets/controller-cert.pem",
  "private_key_file": "/run/response-secrets/controller-key.pem",
  "remote_revision": "REPLACE_WITH_THE_64_CHARACTER_ENFORCER_REVISION"
}
```

For a native endpoint, use `type: "linux_endpoint"`, `platforms: ["linux"]`,
and the stable device ID from that endpoint's configuration. Its integration ID,
target map and remote revision must agree with the service. The endpoint checks
that the controller's actual peer IP is covered by its preserved management
networks before it accepts an isolation command.

The controller configuration is nonsecret metadata. Put private keys, CA files,
and provider tokens in a separate directory readable by container UID 65532.
The API mounts only the JSON file; the worker mounts the secret directory.
Do not add credentials, private keys or real device inventories to Git.

Set absolute paths in the customer's environment file:

```text
RESPONSE_CONFIG_PATH=/etc/aegisndr/response.json
RESPONSE_SECRETS_DIR=/etc/aegisndr/response-secrets
```

Use the existing production TLS overlays plus the opt-in response overlay:

```bash
docker compose -f infra/compose/docker-compose.yml \
  -f infra/compose/docker-compose.internal-tls.yml \
  -f infra/compose/docker-compose.https.yml \
  -f infra/compose/docker-compose.response.yml \
  --env-file /path/to/customer.env \
  --profile customer --profile response up -d --build
```

The worker has private store access and a separate response egress network; the
Local API gains no outbound response network or provider credentials. Worker
state uses PostgreSQL and survives container replacement. Health is available in
the Response page and the worker's Compose health check. Initialization requires
the real production store settings, including the internal TLS CA.

The worker reloads its configuration every five seconds. Restart the Local API
after changing its controller configuration, so authorization uses the same
configuration revision. A malformed response configuration disables response in
the API without taking down investigation. A worker configuration/read failure
disables new submissions and attempts reconciliation/recovery with its last
known configuration. Both paths remain scoped to the installed deployment.

## 3. Configure Defender when required

Use a dedicated application limited to an exclusive managed device group. Keep
other automation from issuing isolation changes in that group. Supply its
short-lived access token through a local file, refreshed atomically by your
credential service; the adapter rereads it per request. This implementation does
not create an Entra application, grant permissions, or mint provider credentials.
The provider identity needs the applicable isolation and machine/action read
permissions. Match `requestor` to the actual identity returned in MachineActions.

```json
{
  "id": "lab-defender",
  "type": "defender",
  "endpoint": "https://api.security.microsoft.com",
  "platforms": ["Windows10", "Windows11"],
  "targets": {"0000000000000000000000000000000000000001": ["192.0.2.10"]},
  "device_groups": ["123"],
  "requestor": "REPLACE_WITH_THE_ACTUAL_PROVIDER_APPLICATION_IDENTITY",
  "exclusive_device_group": true,
  "isolation_type": "Full",
  "access_token_file": "/run/response-secrets/defender-access-token",
  "verification": {
    "endpoint": "https://endpoint-management.customer.example:9443",
    "ca_file": "/run/response-secrets/probe-ca.pem",
    "certificate_file": "/run/response-secrets/controller-cert.pem",
    "private_key_file": "/run/response-secrets/controller-key.pem",
    "remote_revision": "REPLACE_WITH_THE_64_CHARACTER_PROBE_REVISION"
  }
}
```

Run the same service in `probe` mode on the device, using
`infra/response/probe.example.json` and a writable `--database` path appropriate
to its OS. Probe mode does not invoke nftables or require network-admin rights.
It supports Python on Windows/Linux; provide your normal OS service supervision.
Its pinned `device_id` must be the Defender machine ID. Configure two to four
distinct, fixed canary IPs/ports that are reachable before isolation and should be
blocked afterward. Probe requests contain only a nonce; callers cannot select
arbitrary scan destinations. Mixed canary results are indeterminate.

Preserve the probe's management channel under the selected Defender isolation
policy. If the product/policy cannot preserve it, this adapter will remain
unverified rather than claiming containment succeeded. Verify this prerequisite
before enabling an integration. Native endpoint isolation needs no external
probe because its exact local enforcement rules are read back directly.

The adapter verifies machine ID, configured RBAC group, OS, current address,
active health, noncritical provider classification and reachable canaries before
submission. It correlates provider operations with action ID, proposal hash and
requestor identity, then requires successful provider state plus consistent
probe results. It refuses pre-existing or later unrelated isolation changes.
Bounded history that is incomplete, unavailable or ambiguous stays unknown.

Defender isolation is aggregate device state and its release API offers no
per-controller restriction handle or compare-and-swap. Exclusive group ownership
is an operational prerequisite; an administrator racing this controller can
still change device state between checks and a provider call. Canary checks
measure configured paths, not every possible communication channel. Do not
describe this as mathematical proof of total endpoint isolation.

See the provider's [isolate API](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine),
[action status](https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction),
[action history](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineactions-collection),
and [release API](https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine).

## 4. Enable approved execution, then bounded autonomy

1. Register verified, noncritical assets in the Response page. Bind them to the
   exact configured integration/target IDs and platform strings. Updates require
   the current asset revision; the UI preserves other family bindings.
2. Set policy to Simulate, allow only selected groups/families, and review local
   evidence and exclusions using individual or recent-alert simulation.
3. Complete lab acceptance below. Set controller `enabled: true`, restart the
   Local API, and confirm a matching worker heartbeat. This opens the deployment
   gate; it does not change the policy mode by itself.
4. Select Human approval required. A proposer and a different authorized
   approver must review the exact target and proposal. Observe submission,
   effective verification and release as separate stages.
5. Define exact detector/severity/group/family rules before selecting Bounded
   automatic policy. To create proposals continuously from current alerts, also
   set `automatic_proposals: true` in the controller configuration and restart
   the API to refresh its displayed configuration. The worker scans at most 50
   recent alerts per cycle and deduplicates each alert/asset/family combination.
   A released action is not automatically repeated for the same combination.

All new execution rechecks freshness, policy, critical exclusions, group scope,
capacity and hourly limits. The model is not an authorization input. A matching
immutable detector-provenance hash is required for automatic actions, so raising
an alert's triage severity cannot grant containment authority. Legacy/manual
alerts without provenance require human approval. A matching
healthy worker is required for authorization. Pending approvals expire; changed
asset, evidence, alert, policy or adapter revision invalidates authorization.
Worker leases and provider reconciliation prevent blind resubmission after a
lost response. Verified restrictions are periodically observed again.

## Recovery and operational limits

Use the Response emergency stop to prevent new authorization and submission.
It does not cancel calls already in flight or remove an existing restriction.
Request verified release separately. Disabling new execution still permits
recovery through the original configured adapter.

Firewall address elements expire in the kernel even when the controller or
enforcer stops. The service never extends the original deadline on restart.
Endpoint isolation requires explicit release; it is restored from durable
intent after an enforcer restart/reboot. Keep the service enabled after
`nftables.service` so a later ruleset reload does not erase restored restrictions.
Any firewall reload or host network change can affect enforcement; read-back
failures become unknown rather than remaining reported as protected.

If the controller is unavailable, a local administrator can release an owned
native action using the original service configuration and database:

```bash
python3 services/response-enforcer/app.py \
  --config /etc/aegisndr-response/enforcer.json \
  --database /var/lib/aegisndr-response/enforcer.sqlite3 \
  --release-action ACTION_UUID
```

Stop `aegisndr-response-enforcer.service` before running local recovery, then
restart it after release. A process lock rejects concurrent service/CLI access
to the same database. Stopping the service leaves existing kernel rules in place;
the recovery command persists a release tombstone before the service resumes.

This removes only that action's table. It does not flush other firewall rules.
An endpoint administrator can also recover through their normal host/vendor
management tools; the worker then reports external or ambiguous changes instead
of silently claiming ownership. Back up both PostgreSQL and the enforcer SQLite
database. Lost ownership state is not reconstructed from a name alone.

Keep the original integration revision available until all its actions have been
released. Changing targets, management exceptions or adapter configuration paths
configuration pins invalidates new use of old proposals and can prevent recovery
through a replacement configuration. Credential rotation at the same file path
does not change the nonsecret configuration revision.

Controller certificate fingerprints are authentication settings and are excluded
from the native enforcement revision. Rotate with a temporary old/new pin overlap,
restart the enforcer, replace the worker certificate/key at the same paths, then
remove the old pin and restart the enforcer again. Existing restrictions retain
their ownership and recovery binding throughout. Target, scope, management and
enforcement-setting changes still invalidate the revision. The mTLS lab exercises
certificate replacement while a restriction is active, then verifies release.

The controller is single-node, with at most 1,000 registered assets, 1,000 pending
approvals and 100 active restrictions. Unknown outcomes consume capacity.
Response history is retained without an automatic archive/prune job; monitor its
storage growth. The enforcer has one active endpoint isolation or at most 100
gateway actions. These limits are explicit initial implementation bounds.

## Lab acceptance before production

Run `bash scripts/test-response-enforcement.sh` on a Linux Docker host. It creates
temporary, isolated management/data networks and grants `NET_ADMIN` only inside
its disposable containers. It verifies native endpoint IPv4/IPv6 isolation,
management access, durable restart recovery, release/replay behavior, forwarded
gateway traffic and kernel timeout without controller polling. It also checks
that an unrelated firewall table survives, and drives the real native adapter
over mTLS through apply, observation and release. Missing client certificates and
valid but unpinned controller certificates must be rejected. CI runs this gate
independently; separate regressions exercise connection capacity and stalled TLS
handshakes, and render the response overlay to verify its credential boundaries.

Run backend discovery, frontend suites and the production build as well. These
checks do not replace acceptance against the customer's actual Defender tenant,
configured device groups, management path and independently operated canaries.

Exercise tenant/role separation, independent approval, stale/replayed proposals,
critical exclusions, parallel workers, crashes around submission, expired leases,
lost provider replies, token rotation, throttling, IPv4/IPv6, management access,
kernel TTL expiry with the controller stopped, endpoint service restart/reboot,
and verified release that preserves unrelated restrictions. Measure traffic at
the actual enforcement point. No production containment or lab acceptance is
performed merely by adding this source code and deployment guide.
