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
- Fixed, rate-limited network discovery adapter
- Asset and service inventory
- Safe defaults, explicit exclusions and cancellation

## Phase 3 — Vulnerability intelligence
- CVE/CPE correlation and source attribution
- Evidence-backed risk scoring
- Deduplication and finding lifecycle
- Remediation guidance and report export

## Phase 4 — AI analysis and monitoring
- OpenAI, Anthropic Claude and Ollama adapters
- Structured output and provenance
- AI prioritization and natural-language explanations
- Scheduled re-assessment, drift detection and alerts

## Phase 5 — Cloud and operational hardening
- Cloud control-plane deployment
- Local worker connectivity and certificate rotation
- Kubernetes deployment and secret manager integration
- Load, chaos, security and disaster-recovery testing

The timeline is intentionally milestone-based. Do not enable active scans until the Phase 1 authorization controls and Phase 2 scope enforcement have passed security tests.
