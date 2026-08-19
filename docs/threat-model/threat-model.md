# MVP threat model

| Threat | Control | Verification |
|---|---|---|
| Cross-tenant access | Tenant required in identity and every repository query | Tenant-isolation tests |
| Forged identity headers | Production accepts only signed Logto organization tokens; headers cannot supply actor, role, tenant, or permissions | JWT/API integration tests |
| JWT algorithm/key confusion | RS256 allowlist, keyed JWKS lookup, RSA key constraints, strict base64/JSON parsing, issuer/audience/time checks | Identity boundary tests |
| Cross-organization/deployment token reuse | Signed organization, internal tenant, and deployment claims are checked before routing | Identity boundary tests |
| Prompt injection in logs | Evidence treated as data; control characters and tool-call syntax removed; field limits | Redaction and injection tests |
| Sensitive data exfiltration | Strict/Balanced allowlists, tokenization, forbidden-field scan | Transmission-policy tests |
| Fabricated evidence | Model evidence IDs must be a subset of the submitted local IDs | Response-validation tests |
| Unsafe response action | Recommended actions validated against an allowlist; containment requires approval | Agent tests |
| Gateway retention drift | Calls fail closed unless zero-retention and caching policy are verified | Gateway policy tests |
| Replay of enrollment token | Single-use, 15-minute expiry, atomic exchange | Control-plane tests |
| Cloud-initiated access | Customer connector is outbound-only; no tunnel or remote shell | Compose/network review |
| Default credential exposure | Installer generates secrets; data services are internal-only; `.env` files are gitignored and only `.env.example` placeholders are tracked | Preflight/Compose checks, `.gitignore` audit |
| Audit tampering | Append-only chained hashes and exportable records | Audit-chain tests |

## Explicitly prohibited capabilities

The local agent has no arbitrary SQL, shell, unrestricted URL, arbitrary file-read, sensor-disable, or unapproved isolation tool. The cloud receives no raw packet payloads, credentials, internal IPs/hostnames, usernames, file paths, cookies, authorization headers, or document content.
