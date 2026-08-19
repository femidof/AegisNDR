# Private-LAN HTTPS ingress

Production customer appliances expose one browser origin:

```text
https://<trusted-lan-host>/          analyst dashboard
https://<trusted-lan-host>/api/     customer-resident Local API
https://<trusted-lan-host>/grafana/ customer-resident Grafana
```

The additive `infra/compose/docker-compose.https.yml` file removes the base
dashboard, API, and Grafana host ports before publishing ports 80 and 443 on the
configured trusted interface. PostgreSQL, ClickHouse, MinIO, Prometheus, and
all exporters remain un-published. Port 80 accepts no application traffic; it
only returns a permanent redirect to the configured HTTPS origin. Requests
with a different `Host` value are rejected.

The dashboard and Local API are same-origin in production. This avoids a
credential-bearing cross-origin API path and gives the OIDC PKCE client the
secure browser context required by WebCrypto. The separately hosted Logto
browser endpoint must also use HTTPS and is allowlisted in the ingress Content
Security Policy through `LOGTO_PUBLIC_ENDPOINT`. The Logto Admin endpoint stays
on its separately configured operator hostname and is not proxied by the
customer appliance.

## Installer-managed certificate

Pass the hostname or IPv4 address that analysts actually enter in their
browsers:

```bash
sudo ./installer/install.sh \
  --interface ens18 \
  --bind-address 192.168.1.50 \
  --lan-host ndr.customer.example \
  --control-plane-url https://control.example.com \
  --enrollment-token-file /run/hybrid-ndr-enrollment.token \
  --non-interactive
```

When no server certificate is supplied, the installer creates a private P-256
LAN CA and a server certificate with the exact hostname/IP as a Subject
Alternative Name. They are stored under `/etc/hybrid-ndr/tls`; the CA and leaf
are reused across idempotent upgrades, and a mismatched or expiring generated
leaf is renewed from the same local CA.

Before opening the dashboard, distribute
`/etc/hybrid-ndr/tls/ca-cert.pem` to analyst workstations through the
customer's authenticated device-management channel and add it to the managed
browser/OS trust store. Also create the corresponding private DNS record (or
managed hosts entry). Do not distribute `ca-key.pem` or `server-key.pem`.

## Enterprise or public certificate

Supply an unencrypted PEM private key and a PEM leaf/full-chain certificate.
For a private enterprise CA, also supply the validation bundle:

```bash
sudo ./installer/install.sh \
  --interface ens18 \
  --bind-address 192.168.1.50 \
  --lan-host ndr.customer.example \
  --tls-cert /run/tls/ndr-fullchain.pem \
  --tls-key /run/tls/ndr-key.pem \
  --tls-ca /run/tls/customer-ca-bundle.pem \
  --control-plane-url https://control.example.com \
  --enrollment-token-file /run/hybrid-ndr-enrollment.token \
  --non-interactive
```

The installer rejects malformed, encrypted, expired, wrong-host, wrong-key, or
untrusted private-CA material before Compose starts. If `--tls-ca` is omitted,
post-install health uses the appliance's system public-CA trust. To replace or
rotate supplied material, rerun the verified installer with all applicable TLS
arguments.

## Explicit HTTP development mode

The base Compose file and `.env.example` retain ports 4173, 8080, and 3001 only
for loopback/local development. That environment explicitly sets
`DASHBOARD_ALLOW_INSECURE_HTTP=true`; the dashboard rejects insecure API mode
on any non-loopback browser origin. Every installer deployment adds the HTTPS
overlay, forces that flag to `false`, and validates all three services through
the TLS ingress before recording a successful install.

Production health endpoints are available through the trusted origin at
`/_health/ingress`, `/_health/dashboard`, `/_health/api`, and
`/grafana/api/health`. They disclose only service readiness.
