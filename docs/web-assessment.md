# Phase 3.1 web assessment coverage

SentinelAI has two independent execution paths:

- `network-inventory-passive` records passive, policy-validated inventory declarations.
- `web-assessment-passive` and `web-assessment-safe-active` run bounded HTTP/browser checks against an explicitly authorized web scope.

## Implemented checks

| Check | Passive | Safe active | Result |
|---|---:|---:|---|
| CSP, HSTS, X-Content-Type-Options, Referrer-Policy | Yes | Yes | Evidence-backed missing-header findings |
| Cookie Secure/HttpOnly observation | Yes | Yes | Redacted `Set-Cookie` evidence |
| Wildcard CORS observation | Yes | Yes | Medium finding; application-specific review remains required |
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
