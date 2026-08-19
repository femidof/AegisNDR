# Customer appliance installer

The installer deploys only the `customer` Compose profile: sensors, Vector,
ClickHouse, PostgreSQL, MinIO, the local API and dashboard, Prometheus, Grafana,
and related local exporters. It refuses a profile that resolves `logto`,
`logto-postgres`, or `control-api`. Those are vendor-plane services and must not
run on a customer appliance.

## Trust bootstrap

Distribute the release public key (or its DER SHA-256 pin) to the customer by an
authenticated channel separate from the release. Never download an installer
and pipe it into a shell. Download the bundle, checksum, and binary signature as
files, then verify them as an unprivileged user before using `sudo`:

```bash
export PRODUCT_RELEASE_PUBLIC_KEY_SHA256='<out-of-band DER public-key SHA-256>'
./installer/verify-release.sh \
  --public-key /usr/local/share/hybrid-ndr/release-public.pem \
  hybrid-ndr-1.2.3-offline.tar.gz \
  hybrid-ndr-1.2.3-offline.tar.gz.sha256 \
  hybrid-ndr-1.2.3-offline.tar.gz.sig

./scripts/verify-offline-bundle.sh \
  --public-key /usr/local/share/hybrid-ndr/release-public.pem \
  hybrid-ndr-1.2.3-offline.tar.gz \
  hybrid-ndr-1.2.3-offline.tar.gz.sha256 \
  hybrid-ndr-1.2.3-offline.tar.gz.sig
```

The second command also rejects absolute paths, traversal, links, devices,
duplicate members, oversized expansion, missing customer payloads, and an image
archive whose digest does not match the signed manifest.

After that unprivileged verification, extract the same verified artifact to a
stable, versioned release directory. The privileged verification below repeats
the cryptographic checks; it is not the first verification:

```bash
sudo install -d -m 0755 /opt/hybrid-ndr/releases/1.2.3
sudo PRODUCT_RELEASE_PUBLIC_KEY_SHA256="$PRODUCT_RELEASE_PUBLIC_KEY_SHA256" \
  ./scripts/verify-offline-bundle.sh \
  --public-key /usr/local/share/hybrid-ndr/release-public.pem \
  --extract-to /opt/hybrid-ndr/releases/1.2.3 \
  hybrid-ndr-1.2.3-offline.tar.gz \
  hybrid-ndr-1.2.3-offline.tar.gz.sha256 \
  hybrid-ndr-1.2.3-offline.tar.gz.sig
```

## Initial installation

Requirements are Linux on x86-64 or ARM64, Docker Engine 24+, Docker Compose
2.24+, 4 CPU cores, 8 GiB RAM, 20 GiB free disk, and free HTTPS ingress ports
80 and 443. The Docker daemon must be available to the installing user. The
capture interface must exist and be up; loopback is rejected unless explicitly
enabled for testing.

Place the single-use enrollment token in a mode-0600 file. The installer copies
it only into a temporary mode-0600 request area and deletes both that area and
the source token file immediately after a successful exchange. It never writes
the token to the environment, Compose configuration, logs, or install state.

Online image flow:

```bash
sudo chmod 0600 /run/hybrid-ndr-enrollment.token
sudo /opt/hybrid-ndr/releases/1.2.3/payload/hybrid-ndr/installer/install.sh \
  --project-dir /opt/hybrid-ndr/releases/1.2.3/payload/hybrid-ndr \
  --interface ens18 \
  --bind-address 192.168.1.50 \
  --lan-host ndr.customer.example \
  --control-plane-url https://control.example.com \
  --control-plane-ca /etc/ssl/certs/customer-control-plane-ca.pem \
  --enrollment-token-file /run/hybrid-ndr-enrollment.token \
  --non-interactive
```

Offline image flow (the control-plane enrollment exchange still requires
outbound HTTPS):

```bash
BUNDLE_ROOT=/opt/hybrid-ndr/releases/1.2.3
IMAGE_SHA256=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["images"]["sha256"])' \
  "$BUNDLE_ROOT/BUNDLE-MANIFEST.json")

sudo "$BUNDLE_ROOT/payload/hybrid-ndr/installer/install.sh" \
  --project-dir "$BUNDLE_ROOT/payload/hybrid-ndr" \
  --interface ens18 \
  --bind-address 192.168.1.50 \
  --lan-host ndr.customer.example \
  --control-plane-url https://control.example.com \
  --enrollment-token-file /run/hybrid-ndr-enrollment.token \
  --offline-images "$BUNDLE_ROOT/images.tar" \
  --offline-images-sha256 "$IMAGE_SHA256" \
  --non-interactive
```

For local development only, HTTP is accepted for an exact `localhost` or
`127.0.0.1` control-plane URL when `--allow-insecure-control-plane` is present.
That mode also accepts the MVP control API's non-X.509 demo certificate. It must
not be used on a real appliance.

## Enrollment and private material

The first install creates a local ECDSA P-256 key and CSR. Enrollment uses a
persisted idempotency key so a network retry can retrieve the same response
without reusing the one-time token as a new exchange. The issued certificate,
fingerprint, tenant/deployment IDs, entitlements, policy, and Logto dashboard
configuration are stored under `/var/lib/hybrid-ndr/identity`. The installer
rejects a non-HTTPS remote issuer, a JWKS URL that does not belong to that
issuer, malformed client/organization IDs, missing organization scopes, or an
`offline_access` request. It copies only the validated issuer, JWKS, client,
organization, and scopes into `customer.env`; there is no manual customer-side
OIDC configuration step. Private directories are mode 0700 and key, CSR,
certificate metadata, environment, secret, and state files are mode 0600. The
private key never leaves the appliance.

After enrollment, the outbound-only `deployment-connector` runs continuously.
It sends allowlisted health and aggregate usage, refreshes entitlements and
model policy, verifies signed digest-pinned update manifests, and rotates the
deployment certificate before expiry. Each operation has an independently
persisted schedule and idempotency key with bounded exponential backoff, so a
control-plane outage does not affect local capture or detection. No inbound
connector port is published. An explicitly configured private control-plane CA
is copied into the connector's read-only identity mount.

The installer publishes a host-locked HTTPS ingress on ports 80 and 443. Use
`--bind-address` with the appliance's trusted LAN IP to restrict access to that
interface, and set `--lan-host` to the DNS hostname or IPv4 address analysts
actually use. Dashboard, Local API, and Grafana remain internal and are routed
at `/`, `/api/`, and `/grafana/` on that one origin. Databases and object
storage have no published ports.

If `--tls-cert` and `--tls-key` are omitted, the installer generates a local
private CA and an exact-SAN server certificate. The CA certificate at
`/etc/hybrid-ndr/tls/ca-cert.pem` must be installed in managed analyst browser
or OS trust stores before login so the PKCE client receives a valid WebCrypto
secure context. Enterprise/private certificates can be supplied with
`--tls-cert`, `--tls-key`, and `--tls-ca`; public certificates omit `--tls-ca`.
See [`private-lan-https.md`](private-lan-https.md) for routing, trust, rotation,
and explicit development-HTTP details.

All database, object-store, exporter, and Grafana credentials are generated
locally with OpenSSL. No default `replace-with-generated-secret` value is used.
Every internal credential-bearing hop is additionally encrypted: the installer
provisions a private internal CA (`<state-dir>/internal-tls/`) and applies the
internal-TLS Compose overlay so PostgreSQL, ClickHouse, MinIO, exporters,
Vector, and Grafana communicate over verified TLS with clients pinning the
internal CA.

## Upgrade and recovery

Run the verified installer from the new versioned release directory with the
same interface and without an enrollment token. The installer preserves the
existing environment, generated secrets, ECDSA keys, ingress certificate/CA,
deployment certificate, identity, and
named volumes; applies Compose changes idempotently; and replaces `install-state`
only after post-install container and HTTPS health checks pass. Downgrades require
the explicit `--allow-downgrade` flag.

If enrollment succeeds but service startup fails, rerun the installer without a
token after correcting the service failure. The certificate was already stored
atomically, and the consumed token is not needed again. A failed health gate
does not erase existing volumes or evidence, and the update agent restores the
previous release (configuration and pinned container images) automatically.

## Data-preserving uninstall

```bash
sudo /opt/hybrid-ndr/releases/1.2.3/payload/hybrid-ndr/installer/uninstall.sh \
  --project-dir /opt/hybrid-ndr/releases/1.2.3/payload/hybrid-ndr
```

Uninstall runs `docker compose down` only for the customer project. It never
passes `--volumes` or `--rmi`, and never removes `/etc/hybrid-ndr`,
`/var/lib/hybrid-ndr`, certificates, audit records, evidence, or named volumes.
Evidence destruction is intentionally a separate retention-governed operation.

## Build an offline release

The signing key belongs in an isolated release/CI environment, not on an
appliance:

```bash
./scripts/build-offline-bundle.sh \
  --output-dir ./release \
  --version 1.2.3 \
  --signing-key /secure/release-private.pem
```

This pulls/builds the customer profile, saves all resolved images, excludes
runtime data, `.env`, secrets, caches, and development dependencies, hashes the
image archive in the manifest, then creates a checksum and OpenSSL SHA-256
signature for the complete bundle. `--skip-images` exists only for code-bundle
tests and is not an offline installation artifact.

## Current limitations

- Vendor Logto is deliberately not installed on the appliance. Its HTTPS
  identity origin must be reachable from analyst browsers and the local API;
  enrollment configures that origin automatically.
- Fully air-gapped deployments use `--standalone`: the installer provisions
  local tenant/deployment identity, a locally signed deployment certificate,
  a local RS256 issuer key, and the update-signing trust pin with no outbound
  connectivity. The local API serves the JWKS (`/api/v1/system/jwks`) and
  issues short-lived analyst tokens through `/api/v1/system/standalone-login`
  using the bootstrap secret written to
  `<config-dir>/secrets/standalone-login-secret`. Standalone mode disables the
  deployment connector and vendor identity; it never requires a control plane.

Run installer regression tests with `./scripts/test-installer.sh`.
