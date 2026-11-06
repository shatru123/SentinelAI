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

## Customer-local Worker connectivity boundary

The Worker uses the mTLS listener for its registration and heartbeat calls, but it also consumes RabbitMQ directly and uses a separate PostgreSQL worker principal for assessment state. It is therefore not yet a single outbound-HTTPS-only customer agent. The current `sentinelai-api-worker` Kubernetes Service is internal (`ClusterIP`); the public HTTP Ingress does not expose the mTLS listener.

Do not expose PostgreSQL or RabbitMQ publicly. Before deploying a worker outside the trusted cloud network, provide private connectivity to tenant-scoped broker/database endpoints (or implement a control-plane gateway that removes those direct connections), and publish a TCP/TLS-passthrough endpoint for mTLS. Verify certificate SAN/trust, broker permissions, DB grants, tenant queue routing and cancellation from a real customer-network worker. Until then, deploy the Worker only in the controlled network where those private dependencies are reachable.

## Shared Web authentication key ring

Production Web replicas use one shared ASP.NET Core Data Protection key ring so authentication cookies remain readable across replicas and pod replacement. The Kustomize base creates the `sentinelai-web-data-protection` PVC with `ReadWriteMany` access and mounts it at `/var/lib/sentinelai-data-protection`. The required StorageClass name is `sentinelai-shared-rwx`; provision it using the cloud provider's encrypted shared-filesystem service before deployment. It must support concurrent read/write access from all Web replicas, durable storage and encryption at rest.

The Data Protection key XML is additionally encrypted with a PFX from the external secret manager. Staging/production ExternalSecret templates read:
- `<environment>/sentinelai/pki/web-data-protection-current-pfx`
- `<environment>/sentinelai/pki/web-data-protection-previous-pfx`
- `<environment>/sentinelai/pki/web-data-protection-pfx-password`

At initial provisioning, set the previous PFX to the same certificate as current (or otherwise ensure every certificate referenced by an existing key-ring entry is available). When rotating the encryption certificate, update current to the new PFX and previous to the old PFX; the application encrypts newly generated key-ring entries with current and can decrypt entries protected by either certificate. Keep all older decryption certificates required by the retained key-ring entries; do not discard an old PFX while keys encrypted with it may still be needed. Certificate secret changes require a controlled Web rollout so each replica reloads the mounted PFX material. Never commit PFX files or passwords.

The local Development overlay explicitly removes the shared PVC, certificate secret mount and environment-specific password so `docker compose` and local Kubernetes do not depend on a cloud file service or external secret provider. Staging/production deployment remains blocked until the RWX StorageClass, storage encryption, ExternalSecret values and multi-replica cookie continuity have been validated in a real cluster.

## Signed image release

The manual `.github/workflows/release-images.yml` workflow builds the API, Web and Worker images, pushes immutable digest references to GHCR, emits SBOM/provenance metadata and signs the images using GitHub OIDC with Cosign. It is not run by ordinary CI; no registry image has been published until an operator dispatches the workflow.

Use `deploy/kubernetes/scripts/promote-image-digests.sh` to pin the generated API/Web/Worker digests into the staging or production Kustomize overlay. Commit and review that overlay change. The deployment script requires Cosign and verifies the GitHub OIDC signature of all three images before applying cluster resources. It pins the migration Job to the exact verified API digest. Promotion does not itself deploy anything.

If GHCR packages are private, the cluster must have a namespace-scoped image-pull Secret (or approved node-level registry credential provider) attached to the API, Web, Worker and migration service accounts before rollout. These manifests do not include registry credentials or personal access tokens. Alternatively, package visibility must be explicitly set to public under the release policy. The operator running Cosign verification also needs GHCR read access.
