# Development

## Phase 1 behavior

The API uses development header authentication only when the environment is Development (or `Authentication:UseDevelopmentHeaders` is explicitly enabled). Production expects an OpenID Connect-compatible JWT authority. Every operator request carries a tenant and user claim, and application queries filter by tenant.

The Phase 1 worker lifecycle uses an in-process bounded queue and a deterministic mock adapter. A job is persisted as `Queued`, processed as `Running`, and completed with an audit event and a passive asset record. No active network probing is enabled.

## Database

Development defaults to EF Core InMemory. Production uses PostgreSQL and the migration in `src/SentinelAI.Infrastructure/Migrations`. Set `Database:ApplyMigrations=true` only for a controlled startup path.

## Safety boundary

`SentinelAI.Security.Policy` is deterministic and independent of AI providers. It validates authorization evidence, expiration, target shape, private/public target rules, operation profiles, exclusions and execution-time target membership. AI provider adapters are advisory placeholders until the provider gateway milestone is implemented.

## Useful commands

```bash
dotnet restore SentinelAI.slnx
dotnet build SentinelAI.slnx
dotnet test SentinelAI.slnx
docker compose --env-file .env.example -f deploy/docker/docker-compose.yml config --quiet
```
