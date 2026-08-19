# End-to-end demonstration

## Browser-authenticated journey

The identity plane, customer dashboard, and cloud portal can be exercised by a
real browser against the composed Logto deployment:

```bash
bash scripts/test-browser-oidc.sh
```

The script starts the vendor Logto services, reconciles the identity manifest
(`infra/logto/bootstrap.py`), creates the deterministic analyst identity and
`organization_owner` role membership, reconfigures the dashboard, and then drives
a headless Chromium through the full journey:

1. The dashboard redirects to Logto, completes PKCE authorization-code
   sign-in, and returns with a session-bound org access token.
2. The signed-in analyst sees real persisted Local API data (not demo data),
   and an in-UI alert status change reaches `PATCH /api/v1/alerts/<id>` and is
   recorded in the hash-chained audit trail under the Logto user identity.
3. The cloud portal signs in with the same identity and renders deployment
   metadata while never showing customer event or evidence content.

The check result and screenshots (`docs/design/oidc-*-signed-in.png`) are the
acceptance evidence. The dashboard and portal journeys each require the
composed Logto vendor profile (`--profile vendor`) and the bootstrapped client
IDs/organization ID rendered into `infra/compose/.env`.

## Manual flow

1. Start the local API and dashboard.
2. Load the seeded traffic fixture or call the demo reset endpoint.
3. Open **Alerts** and choose **DNS tunneling detected**.
4. Review the local findings and evidence IDs.
5. Choose **Start investigation**. Local steps complete whether or not the model gateway is online.
6. Open **View transmission ledger** and confirm that raw logs, PCAP, IPs, hostnames, identities, credentials, and payloads were removed.
7. Review the structured assessment and its evidence citations.
8. Create a case and assign the alert.
9. Disable gateway availability and repeat to demonstrate offline-safe behavior.
10. Open the cloud console view and confirm that it shows only deployment health, version, storage percentage, counts, and usage metadata.

Acceptance requires no manual database intervention.
