# Codex / Antigravity Prompt — SentinelAI Phase 1

You are the principal .NET architect and defensive cybersecurity engineer for this repository.

## First: inspect, do not replace

1. Inspect the existing repository, branches, README, LICENSE, .gitignore and all files before editing.
2. Preserve the existing MIT license and its copyright notice.
3. Preserve useful existing configuration; do not overwrite files blindly.
4. Use the current repository `main` branch unless asked to create a feature branch.
5. Report the detected repository state and provide a short plan before implementation.

## Product

Build SentinelAI, a defensive network security platform with a cloud-capable control plane and local/cloud workers. Initial assessment targets are authorized networks, web/API endpoints and GitHub repositories. Implement network inventory first; represent other target kinds in the domain but do not pretend they are already scanned.

## Stack

- .NET 10 / C#
- ASP.NET Core Minimal APIs
- Blazor Web App
- Clean Architecture and CQRS
- PostgreSQL and EF Core
- RabbitMQ
- OpenTelemetry
- Docker Compose
- xUnit, WebApplicationFactory and Testcontainers
- AI provider abstractions for OpenAI, Anthropic Claude and Ollama

Use stable, compatible package versions and central package management. Do not invent package APIs; verify compile-time usage.

## Solution structure

Create projects for:
- SentinelAI.Api
- SentinelAI.Web
- SentinelAI.Domain
- SentinelAI.Application
- SentinelAI.Infrastructure
- SentinelAI.Contracts
- SentinelAI.Worker
- SentinelAI.Agent.Orchestrator
- SentinelAI.Agent.Network
- SentinelAI.Agent.Vulnerability
- SentinelAI.Agent.Code
- SentinelAI.Agent.Monitoring
- SentinelAI.AI.Abstractions
- SentinelAI.AI.OpenAI
- SentinelAI.AI.Anthropic
- SentinelAI.AI.Ollama
- SentinelAI.Security.Policy

Create tests:
- SentinelAI.UnitTests
- SentinelAI.IntegrationTests
- SentinelAI.SecurityTests
- SentinelAI.ArchitectureTests

Keep the control plane modular rather than prematurely splitting every component into a deployable microservice.

## Phase 1 implementation

### Domain and persistence
Implement Tenant, User, TargetScope, ScanPolicy, AgentJob, AgentExecution, Asset, Finding, Evidence, ApprovalRequest and AuditEvent. Use explicit state transitions, UTC timestamps, concurrency controls and tenant-owned relationships.

Configure PostgreSQL/EF Core, indexes, relationships and migrations. Ensure all tenant-scoped queries enforce tenant boundaries at the application/data-access layer.

### Scope and policy engine
Create ITargetScopeValidator and deterministic implementation. Support explicit IP/CIDR, domain and repository allowlists; exclusions; expiration; approved check profiles; rate and execution limits; authorization evidence.

Deny by default. Resolve and validate destinations immediately before execution. Defend against DNS rebinding, redirects, IPv4/IPv6 edge cases and scope confusion. Do not allow public-target checks without an explicit ownership-verification workflow.

### API and identity
Implement OpenID Connect-compatible authentication setup, Admin/SecurityAnalyst/Viewer/Worker roles, policy-based authorization, tenant isolation, request validation, pagination, ProblemDetails, correlation IDs and OpenAPI.

Endpoints:
- GET /health
- POST /api/scopes
- GET /api/scopes
- POST /api/scans
- GET /api/scans/{id}
- POST /api/scans/{id}/cancel
- GET /api/assets
- GET /api/findings
- worker enrollment/heartbeat endpoints with secure authentication

### Worker
Implement hosted worker with job consumption abstraction, heartbeat, idempotency, cancellation, bounded retry, timeouts, structured logs and graceful shutdown. Start with a mock tool adapter. Do not perform active network scans in Phase 1.

### AI abstraction
Define IAIProvider, IAgentPlanner, IAgentAnalysisService and IAIProviderFactory. Add configuration/adapters for OpenAI, Claude and Ollama where API compatibility can be verified. Never hardcode keys. Treat AI as advisory: all proposed actions must be schema-validated and approved by deterministic policy. No arbitrary shell execution.

### Web
Build a responsive Blazor dark-mode dashboard shell with Overview, Assets, Scans, Findings, Agents and Settings. Use real API-backed data, meaningful loading/empty/error states and development-only seed data.

### Observability and deployment
Instrument API, database and worker with OpenTelemetry traces, metrics and logs. Add Docker Compose for API, Web, Worker, PostgreSQL, RabbitMQ and OpenTelemetry Collector. Use health checks, named volumes and safe local-only port bindings. Include an .env.example containing placeholders only.

### Tests
Test scope validation, tenant isolation, authorization, job lifecycle, cancellation, worker idempotency, malformed requests and security-deny paths. Use Testcontainers for infrastructure integration tests. Add architecture tests preventing forbidden project references.

### Documentation
Update README with actual run commands and current status. Add architecture, security model, deployment and development docs. Preserve the MIT license.

## Non-negotiable safety
- Only assess networks and systems with explicit authorization.
- No credential harvesting, exploitation, persistence, lateral movement or stealth.
- No arbitrary AI-generated commands.
- No execution beyond approved target scope.
- Use fixed typed tool adapters with least privilege and egress controls.
- Require explicit human approval for intrusive operations.
- Audit all sensitive actions and provide cancellation / emergency stop.

## Acceptance criteria
1. dotnet restore/build/test succeed.
2. Compose starts all documented services.
3. Health endpoints work.
4. Authenticated operator can register a bounded target scope.
5. Scan request creates a job; Phase 1 uses mock adapter only.
6. Worker reports and persists lifecycle transitions.
7. Dashboard displays persisted state.
8. Invalid scopes, unauthorized roles and cross-tenant requests are rejected.
9. README commands are reproducible.
10. Do not claim tests or runtime checks passed unless executed.

Implement Phase 1 in small coherent changes. Run build and tests, fix failures, inspect git diff, and report changed files, commands run, test results and remaining work. Do not proceed to active scanning until scope enforcement has passed security tests.
