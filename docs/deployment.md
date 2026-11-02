# Deployment

`deploy/docker/docker-compose.yml` is the Phase 1.1 local deployment. It includes the API, Blazor Web App, standalone worker, PostgreSQL, RabbitMQ, OpenTelemetry Collector, Prometheus, Tempo and Grafana with named volumes, health checks, local-only published ports, a bridge network and resource limits.

The worker is intentionally non-root and does not expose a management port. API-to-worker jobs use durable persistent RabbitMQ queues and a dead-letter queue. Worker-to-control-plane registration and heartbeats use a configured bearer token in the Compose sample; replace the sample token with a secret-manager value and use short-lived JWT/OIDC credentials or mTLS for production. Secrets are supplied through `.env` or a secret manager; `.env.example` contains placeholders only.

OpenTelemetry exports API and worker traces/metrics to the collector. The collector forwards traces to Tempo and metrics to Prometheus; Grafana provisions both data sources and a SentinelAI overview dashboard.

Kubernetes deployment remains a later operational milestone. Before production Kubernetes rollout, implement authenticated worker enrollment, mTLS or short-lived credentials, broker-backed job delivery, certificate rotation, egress policies, secret-manager integration and a tested migration strategy.
