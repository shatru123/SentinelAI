# SentinelAI Roadmap

## Phase 1 — Foundation
- .NET solution and project boundaries
- PostgreSQL/EF Core persistence and migrations
- Identity, RBAC and tenant isolation
- Target scope and scan policy engine
- Scan job lifecycle, audit trail and cancellation
- Worker heartbeat and mock adapter only
- Blazor dashboard shell
- Docker Compose, OpenTelemetry and GitHub Actions
- Unit, integration, architecture and security tests

**Exit criteria:** the solution builds and tests pass; authenticated operator can register a scope, submit a mock assessment, observe worker lifecycle and see persisted results; invalid scope and cross-tenant access are denied.

## Phase 2 — Authorized network inventory
- Worker enrollment and mutual authentication
- CIDR/host scope validation and DNS/IP revalidation
- Fixed passive inventory adapter with policy validation and cancellation
- Asset and service inventory
- Safe defaults, explicit exclusions and cancellation

**Status: Complete.** The passive foundation is implemented. Workers can advertise the `passive-inventory` capability, the fixed adapter records only execution-time validated scope declarations without artificial network-request delays, and asset-service persistence is tenant isolated. Asset observation and reachability timestamps are distinct. Active network discovery remains intentionally disabled until a separately reviewed adapter, egress policy and security test suite are approved.

## Phase 3.1 — Authorized web application assessment
- Dedicated web assessment engine separate from passive network inventory
- Public authorization reuse and explicit private-worker capability routing
- Bounded same-origin discovery, passive headers/cookies/CORS/API-documentation checks and safe active checks
- Redacted evidence, Playwright screenshots and tenant-isolated offline HTML reports
- Authenticated API and Blazor assessment history/report workflow
- PostgreSQL persistence, lease-aware cancellation and worker capability admission

**Status: Complete with bounded coverage and security hardening.** See `docs/web-assessment.md`. Coverage is intentionally limited to the checks documented there; destructive exploitation, credential attacks, arbitrary form submission, active network probing and CVE correlation are not part of this milestone.

## Phase 3.1.1 — Web assessment security hardening
- Policy-enforced Playwright browser sessions using a per-assessment loopback proxy, execution-time scope checks and pinned DNS destinations
- Browser cancellation and lease-loss shutdown with configurable screenshot redaction selectors
- Administrator-provisioned private workers with tenant-scoped IPv4/IPv6 CIDR authorization and effective scope intersection
- Exact public authorization matching by scheme, host, effective port and path boundary
- Idempotent findings, request budgets, assessment check coverage and expanded offline report summaries
- Dashboard workflow for requesting, reviewing and selecting approved public authorizations and approved private workers

This milestone does not add destructive attacks, credential testing, arbitrary form submission, active network discovery or broader exploitation. Unsupported checks remain explicitly identified in reports.

## Phase 3.1.2 — CI, browser isolation and execution integrity
- Genuine Playwright installation from the test output with Chromium executable verification in CI
- Service-worker and WebSocket blocking, loopback proxy shutdown, Host-header validation and exact browser destination enforcement
- Administrator-only worker provisioning, capability updates, private CIDR authorization and atomic audit/revocation
- Lease-checked transactional completion for assessment, execution, job, report pointer and audit state
- Finding-specific screenshot evidence and accurate coverage statuses with no fabricated placeholders

This milestone preserves the passive-only execution boundary and does not add destructive attacks, credential testing, arbitrary form submission, active network discovery or Phase 3.2 vulnerability intelligence.

## Phase 3 — Vulnerability intelligence

**Status: Core Phase 3 complete and CI-verified on PR #3.** Release build, 220 unit tests, 28 integration tests, 10 security tests, 2 architecture tests, Playwright browser setup and Docker Compose validation passed. Deferred non-blocking polish is documented in [phase3-vulnerability-intelligence.md](phase3-vulnerability-intelligence.md).

- CVE/CPE correlation and source attribution
- Evidence-backed risk scoring
- Deduplication and finding lifecycle
- Remediation guidance and report export

## Phase 4 — AI analysis and monitoring

**Phase 4.1 — Provider gateway (in progress on phase4/ai-provider-gateway).** Activates the existing OpenAI Responses, Anthropic Messages and Ollama Chat adapters with bounded non-streaming transport, structured JSON-schema output, token usage/provenance, and authenticated provider readiness diagnostics. No API key is required for the application to start; unconfigured providers remain disabled. AI output remains advisory and cannot grant authorization or dispatch execution. See phase4-ai-provider-gateway.md.

Remaining Phase 4 work:
- Evidence-grounded AI prioritization and natural-language explanations with deterministic policy boundaries.
- Scheduled re-assessment, drift detection and alerts.

## Phase 5 — Cloud and operational hardening
- Cloud control-plane deployment
- Local worker connectivity and certificate rotation
- Kubernetes deployment and secret manager integration
- Load, chaos, security and disaster-recovery testing

The timeline is intentionally milestone-based. Phase 3.1 is an authorized web assessment milestone, while vulnerability intelligence/CVE correlation remains a separate future capability. Do not enable active network scans or destructive web testing until a separate security review and milestone acceptance.
