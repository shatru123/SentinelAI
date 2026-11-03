# Phase 3.1 web assessment coverage

SentinelAI has two independent execution paths:

- `network-inventory-passive` records passive, policy-validated inventory declarations.
- `web-assessment-passive` and `web-assessment-safe-active` run bounded HTTP/browser checks against an explicitly authorized web scope.

## Implemented checks

| Check | Passive | Safe active | Result |
|---|---:|---:|---|
| CSP, HSTS, X-Content-Type-Options, Referrer-Policy | Yes | Yes | Evidence-backed missing-header findings |
| Cookie Secure/HttpOnly/SameSite observation | Yes | Yes | Per-cookie redacted evidence; only sensitive cookies create findings |
| Credentialed wildcard CORS observation | Yes | Yes | Potential finding only when credentials are also enabled |
| Server and OpenAPI/Swagger indicators | Yes | Yes | Informational only |
| Same-origin links/forms and bounded endpoint discovery | Yes | Yes | Persisted endpoint records |
| HTTP `OPTIONS` method observation | No | Yes | Potential TRACE exposure only when advertised |
| Harmless reflected canary on an existing query URL | No | Yes | Potential finding; no JavaScript execution |
| Genuine browser screenshot | Yes | Yes | Playwright PNG, tenant-prefixed artifact key |
| Offline HTML report | Yes | Yes | Escaped HTML with embedded screenshot data URIs |

## Not implemented in this milestone

Injection exploitation, credential attacks, brute force, arbitrary form submission, file upload testing, destructive state changes, broad authorization testing, CVE/CPE correlation, unrestricted proxying and active network discovery are unsupported or not tested. They must not be represented as complete coverage.

## Authorization boundary

Public web targets require a current administrator-approved authorization record. Private targets require an exact tenant worker identity and both `web-assessment` and `private-web-assessment` capabilities. Each request, redirect and discovered URL is revalidated; private DNS must resolve only to allowed private address space. A worker losing its lease or authorization must stop issuing requests.

## Artifacts

Screenshots and reports are stored under a tenant/assessment-prefixed key using `Artifacts:Root`. The API verifies tenant ownership before serving either artifact. Reports are self-contained and do not load external CSS, JavaScript or image URLs.

## Phase 3.1.1 hardening

Browser screenshots run through a fresh, assessment-scoped Playwright context and a loopback policy proxy. Browser routes and the proxy both revalidate HTTP(S) scope, DNS and redirects; the proxy connects only to the validated address pin while preserving the original Host and TLS SNI. Cookies, authentication state and browser profiles are never persisted between assessments. Lease loss, cancellation, scope expiry and request-budget exhaustion close the context and proxy.

Private execution requires administrator provisioning at `POST /api/v1/workers/{identity}/provision` with explicit private IPv4/IPv6 CIDRs. An assessment may select only a range contained by the worker's approved ranges; execution validates the intersection again after DNS resolution. A worker cannot grant itself the private capability or ranges in production registration.

Public authorization IDs are selected from the authenticated dashboard and are matched to the assessment's scheme, effective port, hostname and path boundary. A free-text evidence description does not authorize a public target. The dashboard also exposes approved worker health, capabilities and ranges for private assessment selection.

Each assessment stores idempotent findings, request-budget limits and a check coverage matrix. Reports include severity distribution, confirmed/potential/informational counts, check statuses, skipped/unsupported reasons and finding-specific screenshot metadata. Sensitive screenshot selectors are configurable through the assessment context; the default policy covers password, hidden, token, secret, API-key, session, payment, email and phone fields plus explicit sensitive markers.

## Phase 3.1.2 integrity hardening

CI installs the exact central `Microsoft.Playwright` package version from the UnitTests output, verifies the Playwright assembly/script pair and a real Chromium executable, then runs genuine screenshot coverage. The browser context blocks service workers and WebSockets. The loopback-only proxy independently rejects WebSocket handshakes, mismatched Host headers, malformed authorities, unauthorized schemes, and destinations outside the validated scheme/hostname/effective-port/path boundary. It pins resolved addresses and terminates active connections during shutdown.

Worker registration is not enrollment. An administrator must provision the identity and capabilities first; registration and heartbeat cannot self-grant `web-assessment`, `private-web-assessment` or private ranges. Capability updates and private authorization changes are audited atomically, and revocation takes effect on the next execution-time authorization check.

Reports are published only by the worker completion transaction after the job, execution and assessment still share the active lease. Report storage may contain an orphaned temporary artifact after an interrupted run, but no database report pointer is published. Finding-specific screenshots are associated with their actual finding URL and ID; if safe capture is unavailable, the coverage matrix records `FailedToExecute` and no placeholder image is stored.
