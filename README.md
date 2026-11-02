# SentinelAI

**Autonomous defensive network security platform** built with .NET 10.

SentinelAI is designed to discover and inventory explicitly authorized assets, evaluate exposure, correlate vulnerability intelligence, and produce evidence-backed remediation guidance. It supports a cloud control plane and local workers positioned near private networks.

> **Safety first:** SentinelAI is for systems you own or are explicitly authorized to assess. Every execution must be bound to a validated scope and policy. The initial milestone uses a mock scanner; active network probing is not enabled until the scope engine and a reviewed adapter are implemented.

## Project status

| Milestone | Status |
|---|---|
| Repository foundation and architecture | Complete |
| Phase 1 solution foundation | Complete |
| Phase 1.1 broker-backed worker and security remediation | Complete |
| Authorized network inventory (passive foundation) | In progress |
| Vulnerability correlation | Planned |
| OpenAI, Claude and Ollama providers | Planned |
| Dashboard and monitoring | Planned |
| Cloud/local deployment | Planned |

## Architecture at a glance

- **Control plane:** ASP.NET Core Minimal APIs, authentication, tenant isolation, scope/policy validation, scan orchestration and audit.
- **Execution plane:** separately deployable .NET Worker, local or cloud; outbound authenticated connection to the control plane.
- **Agent runtime:** deterministic orchestration and bounded specialist agents. AI proposes and explains; a deterministic policy engine validates and authorizes.
- **Data:** PostgreSQL, EF Core and RabbitMQ.
- **AI:** provider abstraction for OpenAI, Anthropic Claude and Ollama.
- **UI:** Blazor Web App.
- **Observability:** OpenTelemetry, structured logs, metrics and traces.

See [architecture](docs/architecture.md), [security model](docs/security-model.md), and the [implementation roadmap](docs/roadmap.md).

## Target repository layout

```text
src/
  SentinelAI.Api/
  SentinelAI.Web/
  SentinelAI.Domain/
  SentinelAI.Application/
  SentinelAI.Infrastructure/
  SentinelAI.Contracts/
  SentinelAI.Worker/
  SentinelAI.Agent.Orchestrator/
  SentinelAI.Agent.Network/
  SentinelAI.Agent.Vulnerability/
  SentinelAI.Agent.Code/
  SentinelAI.Agent.Monitoring/
  SentinelAI.AI.Abstractions/
  SentinelAI.AI.OpenAI/
  SentinelAI.AI.Anthropic/
  SentinelAI.AI.Ollama/
  SentinelAI.Security.Policy/
tests/
  SentinelAI.UnitTests/
  SentinelAI.IntegrationTests/
  SentinelAI.SecurityTests/
  SentinelAI.ArchitectureTests/
deploy/
  docker/
  observability/
  kubernetes/
docs/
samples/
```

Begin with a modular control plane plus a separately deployable worker. Split services only when operational needs justify it.

## Prerequisites

- .NET 10 SDK
- Docker Engine/Desktop with Compose
- Git
- Optional: Ollama for local model inference

## Security principles

1. Deny by default: no scan without an explicit, active authorization scope.
2. Scope every job by tenant, initiating principal, allowed targets, exclusions, policy and expiry.
3. Revalidate DNS and resolved addresses immediately before connection; defend against DNS rebinding and redirects.
4. Keep scanner tools behind fixed typed adapters. Never execute arbitrary AI-generated shell commands.
5. Start with passive analysis and safe mock adapters; require human approval for intrusive checks.
6. Restrict worker privileges, egress, CPU, memory, concurrency and execution time.
7. Record append-only audit events and preserve evidence provenance.
8. Treat model output, scanner output, repository files and remote content as untrusted data.
9. Keep provider credentials in runtime secrets or a secret manager; never commit them.
10. Provide cancellation, expiry and an emergency stop mechanism.

Read [SECURITY.md](SECURITY.md) before operating the platform.

## Development

Development defaults to an EF Core in-memory database and an in-memory queue only when explicitly configured in `appsettings.Development.json`; the production and Compose paths use PostgreSQL, RabbitMQ, and the standalone worker. The available execution adapters are bounded passive declaration adapters; active network probing is disabled.

```bash
dotnet restore SentinelAI.slnx
dotnet build SentinelAI.slnx
dotnet test SentinelAI.slnx
dotnet run --project src/SentinelAI.Api
dotnet run --project src/SentinelAI.Web
```

For PostgreSQL, RabbitMQ, the worker, Grafana and the OpenTelemetry Collector:

```bash
cp .env.example .env
docker compose --env-file .env -f deploy/docker/docker-compose.yml up --build
```

Compose applies the checked-in EF migration on API startup when `Database__ApplyMigrations=true`. See [development](docs/development.md) and [deployment](docs/deployment.md) for boundaries and limitations.

The Compose API writes jobs and RabbitMQ outbox messages transactionally. The outbox dispatcher publishes publisher-confirmed, durable messages to tenant-specific queues; `SentinelAI.Worker` consumes them with manual acknowledgements, bounded concurrency, retry/dead-letter handling, per-worker cancellation signals, and restart recovery. Worker credentials are bound to worker identity and tenant assignment, while worker registration and heartbeats are persisted in PostgreSQL and shown through the authenticated API. Public target authorization is a separate operator-request/administrator-approval workflow with evidence and expiry. Set `WORKER_CONTROL_PLANE_TOKEN` and `WORKER_TENANT_ID` in `.env` before a shared deployment; never deploy the Compose Development authentication settings to a shared environment.

Worker credential rotation is supported by configuring a worker credential as `old-token|new-token` during a rollout, then removing the old value or listing it under `Authentication:RevokedWorkerTokens`. Production deployments should store these settings in a secret manager and use JWT/OIDC and/or mTLS at the control-plane edge.

Phase 1.2.2 adds lease-loss cancellation, tenant-and-exact-worker cancellation routing, concurrency-safe legacy job recovery, and heartbeat health admission that does not trust stale capacity counters. Phase 1.2.1 also adds worker-owned expiring leases, PostgreSQL `SKIP LOCKED` outbox claims with backoff, complete-range CIDR validation, DNS exclusion checks for all resolved addresses, and explicit web subdomain authorization. Phase 2.1 hardens the passive inventory workflow end to end through the standalone RabbitMQ worker, separates observation and reachability timestamps, removes declaration-only pacing delays, and verifies tenant-scoped persistence. Phase 2.1.1 serializes PostgreSQL migration tests, backfills legacy reachability history, enforces tenant-consistent asset services at the database level, and prevents cancellation or lease loss from committing pending inventory. The passive foundation records only execution-time validated scope declarations and optional tenant-scoped service observations; it performs no DNS, socket, port or command activity. Active network probing remains disabled.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions must preserve the authorization and execution boundaries.
