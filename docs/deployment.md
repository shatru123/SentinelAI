# Deployment

`deploy/docker/docker-compose.yml` is the Phase 1 local deployment. It includes the API, Blazor Web App, worker, PostgreSQL, RabbitMQ, OpenTelemetry Collector and Grafana with named volumes, health checks, local-only published ports, an internal bridge network and resource limits.

The worker is intentionally non-root and does not expose a management port. Secrets are supplied through `.env` or a secret manager; `.env.example` contains placeholders only.

Kubernetes deployment remains a later operational milestone. Before production Kubernetes rollout, implement authenticated worker enrollment, mTLS or short-lived credentials, broker-backed job delivery, certificate rotation, egress policies, secret-manager integration and a tested migration strategy.
