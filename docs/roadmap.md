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

**Phase 4.1 — Provider gateway (merged into `main` through PR #5).** Activates the OpenAI Responses, Anthropic Messages and Ollama Chat adapters with bounded transport, structured JSON-schema output, token usage/provenance and authenticated readiness diagnostics. The provider gateway and readiness checks are now part of `main`. See phase4-ai-provider-gateway.md.

**Phase 4.2 — Evidence-grounded finding analysis (merged into `main` through PR #6).** Adds explicit Operator-triggered analysis, bounded summaries and redacted evidence input, structured output validation, evidence-ID allow-listing, tenant-scoped persistence and provider/prompt/input-hash/token provenance. AI output remains advisory and cannot mutate findings or authorize execution. See phase4-finding-analysis.md.

**Phase 4.3 — Finding AI analysis UI (merged into `main` through PR #7).** Adds an advisory-only AI analysis section to the finding dossier, explicit provider selection and request for Admin/Security Analyst roles, and persisted history for Readers. Opening a finding never submits it to a provider automatically. UI role checks remain usability controls; API authorization is authoritative. See phase4-finding-analysis-ui.md.

**Phase 4.4 — Scheduled reassessment and drift alerts (implementation merged in PR #8; acceptance closure in PR #9).** Bounded scope-bound schedules, per-occurrence authorization revalidation, transactional outbox dispatch, deterministic drift comparisons and tenant-scoped in-app notifications are implemented. PR #9 closes migration rollback, real API lifecycle, public-authorization revocation, worker-pipeline execution, processor reconciliation, privacy, retry/idempotency and PostgreSQL dispatch/reconciliation concurrency acceptance gaps. Final full CI run #583 passed: 343 tests, 0 failures, 0 skips (289 unit, 42 integration, 10 security, 2 architecture); Release build, Playwright Chromium and Docker Compose validation also passed. TestServer integration now drives a due scheduled run through the real in-process worker and reconciles its completed assessment; browser pages use fixture APIs, with PostgreSQL migration/concurrency paths covered separately. Phase 4 is complete on `main`; the Phase 5 implementation is underway on `phase5/cloud-operational-hardening`. See `phase4-scheduled-reassessment.md`.

**Exported AI advisory summaries (implemented in PR #8).** Operators and readers can explicitly request an HTML report containing the latest persisted evidence-grounded AI summary for each finding. This option is off by default; export performs no AI-provider call and includes advisory labeling and provenance.

## Phase 5 — Cloud and operational hardening

**Status: In progress, not production-ready.** Implementation is underway on `phase5/cloud-operational-hardening` from the merged Phase 4 mainline. The complete requirement-to-evidence matrix is [phase5-workstream-status.md](phase5-workstream-status.md), and the Phase 5.0 topology/threat-model baseline is [phase5-architecture-and-threat-model.md](phase5-architecture-and-threat-model.md). Do not treat individual CI success as a Production release gate.

The Phase 5 execution plan and acceptance gates are maintained in [phase5-cloud-operational-hardening.md](phase5-cloud-operational-hardening.md). The work is divided into four deliverable workstreams:

- Cloud control-plane deployment and production identity/configuration.
- Local worker connectivity, mutual authentication and safe certificate rotation.
- Kubernetes packaging, network policy and external secret-manager integration.
- Load, chaos, security, backup/restore and disaster-recovery validation.

Provider-specific deployment choices remain explicit decisions; credentials, private keys and production secrets must never be committed to the repository.

The timeline is intentionally milestone-based. Phase 3.1 is an authorized web assessment milestone, while vulnerability intelligence/CVE correlation remains a separate future capability. Do not enable active network scans or destructive web testing until a separate security review and milestone acceptance.
