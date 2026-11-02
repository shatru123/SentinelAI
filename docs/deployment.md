# Deployment

`deploy/docker/docker-compose.yml` is the Phase 1.2 local deployment. It includes the API, Blazor Web App, standalone worker, PostgreSQL, RabbitMQ, OpenTelemetry Collector, Prometheus, Tempo and Grafana with named volumes, health checks, local-only published ports, a bridge network and resource limits.

The worker is intentionally non-root and does not expose a management port. API-to-worker jobs use tenant-specific durable persistent RabbitMQ queues, a retry queue and a tenant-specific dead-letter queue. Cancellations use per-worker queues. The API outbox publishes with publisher confirms and retries after a broker outage. Worker-to-control-plane registration binds a configured credential to `Worker__Identity` and tenant assignment; replace the sample token with a secret-manager value and use short-lived JWT/OIDC credentials or mTLS for production. During a credential rotation, configure old and new worker tokens separated by `|`, then remove the old value or add it to `Authentication:RevokedWorkerTokens`. Secrets are supplied through `.env` or a secret manager; `.env.example` contains placeholders only.

Compose is explicitly a local development environment: the API and web services run in the Development environment so the server-configured dashboard login can use development headers. Never carry that setting into a shared or production deployment. Production requires JWT/OIDC for operators and per-worker credentials or mTLS for workers.

OpenTelemetry exports API and worker traces/metrics to the collector. The collector forwards traces to Tempo and metrics to Prometheus; Grafana provisions both data sources and a SentinelAI overview dashboard.

Kubernetes deployment remains a later operational milestone. Before production Kubernetes rollout, implement authenticated worker enrollment, mTLS or short-lived credentials, broker-backed job delivery, certificate rotation, egress policies, secret-manager integration and a tested migration strategy.
