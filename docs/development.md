# Development

## Phase 1 behavior

The API uses development header authentication only when the environment is Development. Production expects an OpenID Connect-compatible JWT authority. Every operator request carries a tenant and user claim, and application queries filter by tenant.

The production worker lifecycle uses RabbitMQ. The API persists a job, audit event and outbox message in one transaction; the outbox dispatcher publishes a durable message with publisher confirmation. The standalone worker consumes tenant-routed jobs with manual acknowledgement, bounded concurrency, retry and dead-letter handling, tenant-and-exact-worker cancellation routing, maximum execution duration, lease-renewal cancellation, idempotent status checks, and restart recovery. Heartbeat capacity is telemetry; the worker semaphore is the admission authority. The in-memory queue is available only when `Messaging:Mode=InMemory`, and an in-process processor is disabled unless `Worker:RunInProcess=true`.

## Database

Development defaults to EF Core InMemory. Production uses PostgreSQL and the migration in `src/SentinelAI.Infrastructure/Migrations`. Set `Database:ApplyMigrations=true` only for a controlled startup path.

## Safety boundary

`SentinelAI.Security.Policy` is deterministic and independent of AI providers. Public targets require a separate persisted request and administrator approval containing evidence, authenticated approver, method, timestamp and expiry; the legacy request Boolean and caller-supplied verification records are ignored. The policy validates strict IPv4/IPv6 and CIDR syntax, special-purpose ranges, IPv6 ULA, domain boundaries, CIDR exclusions, execution-time DNS results, DNS rebinding, and web redirects. The resulting validated execution target pins approved addresses for adapters while preserving the original hostname for protocol headers/SNI. AI remains advisory and cannot add targets or bypass policy.

The Blazor dashboard uses a server-side cookie/OIDC-compatible authentication model. Development login is generated from server configuration and the authenticated principal is translated into API headers; production forwards a saved OIDC access token from the server-side authentication context or encrypted authentication ticket when an interactive circuit has no `HttpContext`. No browser local storage or user-selected tenant header is trusted. Use `/auth/login` for the local development sign-in flow.

## Useful commands

```bash
dotnet restore SentinelAI.slnx
dotnet build SentinelAI.slnx
dotnet test SentinelAI.slnx
docker compose --env-file .env.example -f deploy/docker/docker-compose.yml config --quiet
```

### Run the in-process local development profile

On macOS/Linux, start both applications using the repository launcher:

```bash
bash scripts/dev-local.sh
```

The script starts the API, waits for `/health`, then starts the Web app. Press Ctrl+C to stop both processes.

Alternatively, run the API and Web app in two separate terminals; keep the API terminal running while testing the dashboard.

Terminal 1:

```bash
dotnet run --project src/SentinelAI.Api --launch-profile http
```

Terminal 2:

```bash
dotnet run --project src/SentinelAI.Web --launch-profile http
```

Open `http://localhost:5056/auth/login` once, then continue to `http://localhost:5056/`. The API listens on `http://localhost:5109`. Development API settings use EF Core InMemory, an InMemory queue, and `Worker:RunInProcess=true`; scan jobs are consumed inside the API process. No separate Worker project is required in this mode. The in-memory database is reset whenever the API process restarts.

### Run the full Docker Compose profile

```bash
cp .env.example .env
docker compose --env-file .env -f deploy/docker/docker-compose.yml up --build
```

Open `http://127.0.0.1:5081/auth/login`, then `http://127.0.0.1:5081/`. The local Compose dashboard defaults to the Development Admin role so the first external worker can be provisioned from Setup or Workers. On the Setup page, provision the configured `compose-worker` identity; the separate worker container will then register and begin sending heartbeats. Do not use this Development role configuration in a shared or production environment. Set `DASHBOARD_ROLE=SecurityAnalyst` in `.env` to test a restricted analyst view after the worker has been provisioned.

The browser-facing API is `http://127.0.0.1:5080`; the Web container calls it internally at `http://api:8080`. The Development Web launch profile uses `http://localhost:5109`; do not change it to the Compose host port.

To exercise the broker path, inspect `docker compose --env-file .env -f deploy/docker/docker-compose.yml logs -f api worker`. The worker should log a successful registration after its identity is provisioned. Grafana is at `http://127.0.0.1:3000` with Prometheus and Tempo provisioned from `deploy/observability`; local credentials default to `admin` / `admin` and can be changed with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` in `.env`.

If an API-backed page shows an unavailable-API error, check `http://localhost:5109/health` (local profile) or `http://127.0.0.1:5080/health` (Compose), confirm the Web app's configured API base URL, sign in at `/auth/login`, and restart the Web app after configuration changes.

Phase 1.2.2 integration tests require reachable PostgreSQL and RabbitMQ. Compose publishes them on `127.0.0.1:5432` and `127.0.0.1:5672`; CI provisions both services. The PostgreSQL tests verify migration state, legacy Running-job recovery, persisted heartbeat capacity, concurrent recovery, and database concurrency protection for worker leases. RabbitMQ tests verify manual acknowledgement/retry and cancellation isolation for identical worker identities in different tenants.

## Phase 2 passive inventory foundation

The `network-inventory-passive` profile is authorized like every other operation profile and is available to workers advertising `passive-inventory`. Its fixed adapter revalidates every scope target at execution time, validates the configured request-rate policy, and records an offline/passive observation without adding artificial delays to declaration-only processing. It does not resolve DNS, open sockets, probe ports, execute commands, or claim reachability. `LastObservedAt` records the passive observation time; `LastSuccessfulReachabilityAt` remains nullable and is only populated by an explicitly validated reachability source. Asset services are tenant-scoped and can be retrieved from `/api/v1/assets/{id}/services`.

The existing `mock-passive` profile remains available for compatibility. Do not enable active discovery by configuration alone; an active adapter requires a new security review, explicit egress controls, cancellation tests and authorization acceptance evidence.

## Phase 3.1 authorized web assessment

Web assessment is a separate execution path from `network-inventory-passive`. Select `web-assessment-passive` for bounded passive checks or `web-assessment-safe-active` for the small set of non-destructive OPTIONS/canary checks currently implemented. The supported checks are security headers (CSP, HSTS, X-Content-Type-Options and Referrer-Policy), cookie attributes, wildcard CORS, server disclosure, OpenAPI/Swagger indicators, same-origin endpoint discovery, safe HTTP method observation and harmless reflected-canary observation. Findings are evidence-backed and carry a check status; unsupported or inconclusive coverage is not reported as confirmed.

Public web scopes require an approved `PublicTargetAuthorization` record. Private scopes must set `WebHostingMode=Private`, an exact `PrivateWorkerIdentity`, and run only on a worker advertising both `web-assessment` and `private-web-assessment`. Private DNS results must remain in private address space; loopback, link-local, metadata, multicast and reserved ranges are rejected. Every redirect and discovered URL is revalidated. The worker uses an address-pinned connection callback, preserves the original HTTP Host/SNI name, disables automatic redirects, and never acts as an unrestricted proxy.

Completed assessments persist tenant-scoped endpoints, findings, redacted evidence and genuine Playwright screenshots. The report is an authenticated, self-contained HTML artifact with embedded screenshot data URIs and escaped target-controlled content. Configure `Artifacts:Root` to place files outside the application source tree. The worker image must install the Playwright Chromium dependency before screenshot capture is enabled.

The Phase 2.1 workflow test starts the API, outbox dispatcher and RabbitMQ-backed standalone worker against PostgreSQL. It verifies worker capability admission, execution-time scope validation, passive asset persistence, tenant isolation and audit completion. Run it with the normal integration suite while PostgreSQL and RabbitMQ are available.

Phase 2.1.1 serializes the PostgreSQL-backed integration collection so API-host migration startup cannot race reliability tests. The reachability-history migration backfills `LastSuccessfulReachabilityAt` only for legacy online assets with a null value. Asset services now require a database-enforced `(TenantId, AssetId)` relationship to the matching asset; migration setup fails loudly if legacy orphaned or cross-tenant service rows are found. The migration-upgrade test uses a temporary PostgreSQL schema, applies migrations only through `20261102160000_Phase21AssetObservationSemantics`, inserts legacy rows, and then advances through the real EF migration chain before removing the schema.

Integration tests require RabbitMQ. CI provisions it as a service; locally use the Compose RabbitMQ service or set `RABBITMQ_TEST_HOST`, `RABBITMQ_TEST_PORT`, `RABBITMQ_TEST_USER` and `RABBITMQ_TEST_PASSWORD` before running `dotnet test`. Required broker tests do not silently pass when RabbitMQ is unavailable.

## Phase 3.1.2 integrity hardening

CI installs the exact central `Microsoft.Playwright` package version from the UnitTests output, verifies the Playwright assembly/script pair and a real Chromium executable, then runs genuine screenshot coverage. The assessment browser blocks service workers, WebSockets/WSS and non-GET/HEAD requests, uses a loopback-only policy proxy with a host-only HTTPS CONNECT stage followed by exact scheme/host/port/path checks in Playwright, pins DNS results, and closes outstanding proxy connections on cancellation, authorization revocation or lease loss.

Worker identities and capabilities are administrator-provisioned. Registration and heartbeat report state only; they cannot create, add or retain unapproved capabilities. Private web capability requires `web-assessment` plus administrator-approved private CIDRs. Provisioning and authorization revocation are audited in one database transaction, and revocation is re-read by execution-time authorization checks.

Web assessment report artifacts are temporary until a transaction finalizes the assessment, execution, job, report pointer and completion audit under the current lease. Lease loss, cancellation or a failed finalization cannot publish a completed assessment. Screenshot records are finding-specific where findings exist, include URL/type/timestamp/SHA-256 metadata, and failed screenshot capture is represented as a coverage limitation rather than fabricated evidence.
