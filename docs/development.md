# Development

## Phase 1 behavior

The API uses development header authentication only when the environment is Development. Production expects an OpenID Connect-compatible JWT authority. Every operator request carries a tenant and user claim, and application queries filter by tenant.

The production worker lifecycle uses RabbitMQ. The API persists a job, audit event and outbox message in one transaction; the outbox dispatcher publishes a durable message with publisher confirmation. The standalone worker consumes tenant-routed jobs with manual acknowledgement, bounded concurrency, retry and dead-letter handling, per-worker cancellation, maximum execution duration, idempotent status checks, and restart recovery. The in-memory queue is available only when `Messaging:Mode=InMemory`, and an in-process processor is disabled unless `Worker:RunInProcess=true`.

## Database

Development defaults to EF Core InMemory. Production uses PostgreSQL and the migration in `src/SentinelAI.Infrastructure/Migrations`. Set `Database:ApplyMigrations=true` only for a controlled startup path.

## Safety boundary

`SentinelAI.Security.Policy` is deterministic and independent of AI providers. Public targets require a separate persisted request and administrator approval containing evidence, authenticated approver, method, timestamp and expiry; the legacy request Boolean and caller-supplied verification records are ignored. The policy validates strict IPv4/IPv6 and CIDR syntax, special-purpose ranges, IPv6 ULA, domain boundaries, CIDR exclusions, execution-time DNS results, DNS rebinding, and web redirects. The resulting validated execution target pins approved addresses for adapters while preserving the original hostname for protocol headers/SNI. AI remains advisory and cannot add targets or bypass policy.

The Blazor dashboard uses a server-side cookie/OIDC-compatible authentication model. Development login is generated from server configuration and the authenticated principal is translated into API headers; production forwards a saved OIDC access token from the server-side authentication context. No browser local storage or user-selected tenant header is trusted.

## Useful commands

```bash
dotnet restore SentinelAI.slnx
dotnet build SentinelAI.slnx
dotnet test SentinelAI.slnx
docker compose --env-file .env.example -f deploy/docker/docker-compose.yml config --quiet
```

To exercise the broker path, start Compose and inspect `docker compose ... logs worker api`; the worker should register with the control plane and the RabbitMQ queues should exist. Grafana is at `http://127.0.0.1:3000` with Prometheus and Tempo provisioned from `deploy/observability`; local credentials default to `admin` / `admin` and can be changed with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` in `.env`.

Integration tests require RabbitMQ. CI provisions it as a service; locally use the Compose RabbitMQ service or set `RABBITMQ_TEST_HOST`, `RABBITMQ_TEST_PORT`, `RABBITMQ_TEST_USER` and `RABBITMQ_TEST_PASSWORD` before running `dotnet test`. Required broker tests do not silently pass when RabbitMQ is unavailable.
