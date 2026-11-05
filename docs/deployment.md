# Deployment

## Local development

`deploy/docker/docker-compose.yml` is the supported local runtime. It includes the API, Blazor Web App, standalone worker, PostgreSQL, RabbitMQ, OpenTelemetry Collector, Prometheus, Tempo and Grafana with named volumes, health checks, local-only published ports, a bridge network and resource limits.

Compose is explicitly a local Development environment. Its passwordless dashboard identities, development-header authentication, static worker token and automatic EF migration setting must never be copied into a shared or Production deployment. Production requires OIDC/JWT for operators, tenant-bound mTLS for workers, externalized secrets, PostgreSQL, RabbitMQ and encrypted object storage.

The worker is non-root and does not expose a management port. API-to-worker jobs use tenant-specific durable persistent RabbitMQ queues, retry/dead-letter handling and the transactional outbox. Worker admission continues to require tenant, identity, capability, health, scope, lease and authorization checks.

OpenTelemetry exports API and worker traces/metrics to the collector. The collector forwards traces to Tempo and metrics to Prometheus; Grafana provisions both data sources and a SentinelAI overview dashboard.

## Kubernetes preparation (Phase 5)

Kustomize resources are checked in under `deploy/kubernetes` with `local`, `staging` and `production` overlays. The base defines API/Web workloads, a standalone worker StatefulSet, private services, HTTPS ingress, probes, resource/security contexts, network policies, telemetry and External Secrets Operator resources. Staging and production keep migration prerequisites and the one-shot migration Job in separate release stages before the runtime overlay.

The migration Job runs the API image with `--migrate`. That command follows a database-only startup path and does not load the API's HTTP listener certificate, OIDC configuration or worker mTLS listener. Production API replicas must have `Database__ApplyMigrations=false`; schema migration is a release operation, not a per-replica startup task.

CI renders the local, staging and production Kustomize overlays and validates built-in Kubernetes resource schemas. This is static validation only. It does not prove that a cluster can install or run the resources, that a particular CNI enforces the NetworkPolicies, or that External Secrets Operator can access a real provider.

**The staging and production overlays are templates, not deployable environments yet.** Replace the example hostnames, OIDC issuer/client registration, trusted proxy IPs, bucket/KMS identifiers, tenant/worker IDs and all-zero container image digests. Provision the selected cloud resources, ClusterSecretStore, workload identity, CA and secret values out of band. No provider/account/region has been selected by this repository.

Before any shared or Production exposure, complete a disposable-cluster install/upgrade test, prove external secret injection and rotation, verify mTLS enrollment/rotation/revocation end to end, run load/chaos/security tests, conduct an independent penetration test, and demonstrate the approved backup/restore RPO/RTO. Do not expose the worker directly to the public network.

## Provider-specific egress prerequisites

The Kubernetes base policy allows database and broker traffic to operator-managed pods labelled in the `sentinelai-data` namespace. Staging/production ConfigMap broker hostnames are placeholders. When using cloud-managed PostgreSQL or RabbitMQ outside the cluster, add narrow NetworkPolicy rules for the approved endpoint CIDRs or the selected CNI's FQDN policy before deployment. The default-deny policy must remain in place. The operator-managed egress gateway also needs an explicit destination allow-list for HTTPS dependencies such as OIDC and object storage.
