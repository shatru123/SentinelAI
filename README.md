# SentinelAI

**Autonomous defensive network security platform** built with .NET 10.

SentinelAI is designed to discover and inventory explicitly authorized assets, evaluate exposure, correlate vulnerability intelligence, and produce evidence-backed remediation guidance. It supports a cloud control plane and local workers positioned near private networks.

> **Safety first:** SentinelAI is for systems you own or are explicitly authorized to assess. Every execution must be bound to a validated scope and policy. The initial milestone uses a mock scanner; active network probing is not enabled until the scope engine and a reviewed adapter are implemented.

## Project status

| Milestone | Status |
|---|---|
| Repository foundation and architecture | Complete |
| Phase 1 solution foundation | Complete |
| Mock worker lifecycle | Complete |
| Authorized network discovery | Planned |
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

The Phase 1 control plane defaults to an EF Core in-memory database in Development, so no cloud service is required for the API smoke path. The worker and API use the bounded mock adapter; active network probing is disabled.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions must preserve the authorization and execution boundaries.
