# Kubernetes deployment

The supported local runtime remains Docker Compose. This directory contains the Phase 5 Kubernetes preparation manifests; these are not evidence of a completed or production-ready cluster deployment.

## Layout

- `base/`: API and Web Deployments, worker StatefulSet, services, ingress, service accounts, runtime ConfigMap, network policies, disruption/scaling and telemetry. The one-shot migration Job is kept separate from the runtime base.
- `overlays/local/`: Development-only local data services, local secrets and image tags.
- `overlays/staging/` and `overlays/production/`: environment-specific runtime patches, replica counts and External Secrets Operator resources.
- `scripts/deploy.sh`: context-guarded release sequence for staging and production.

Staging and production remain templates. Their image digests, hostnames, OIDC issuer/client registration, trusted proxy addresses, bucket/KMS identifiers, worker IDs and tenant IDs must be replaced for the selected environment.

The production network policy expects an operator-managed outbound proxy at `sentinelai-egress-gateway.sentinelai-operations.svc.cluster.local:443`, with an HTTP CONNECT-capable proxy endpoint and destination allow-list. API, Web and Worker use `HTTP_PROXY`/`HTTPS_PROXY`; `NO_PROXY` bypasses only loopback and cluster-local services. Web egress is limited to this gateway and the in-cluster telemetry collector. The gateway and its destination policy are cluster-owned dependencies and are not deployed by these manifests.

## Render and validate

From the repository root:

```bash
kubectl kustomize deploy/kubernetes/overlays/local
kubectl kustomize deploy/kubernetes/overlays/staging
kubectl kustomize deploy/kubernetes/overlays/production
bash .github/scripts/validate-kubernetes.sh
bash -n deploy/kubernetes/scripts/deploy.sh
```

CI installs checksum-verified versions of kubectl/Kustomize and kubeconform. It validates built-in Kubernetes resources in all three runtime overlays and separately validates `base/migration-job.yaml`. External Secrets Operator resources are checked for their API group/kind but require the CRDs and a real ClusterSecretStore in the target cluster.

## Sequenced staging/production deployment

After replacing every template value and provisioning the target ClusterSecretStore, CA, identity provider, storage, registry and cluster networking out of band, deploy with an explicit context guard:

```bash
bash deploy/kubernetes/scripts/deploy.sh staging <expected-kubectl-context>
bash deploy/kubernetes/scripts/deploy.sh production <expected-kubectl-context>
```

The script refuses a mismatched context or unresolved placeholders. It applies the namespace, service accounts and base ConfigMap; then applies the environment-specific ExternalSecrets and merges the environment runtime patch. It waits for every ExternalSecret to become Ready before creating the migration Job. The Job uses the exact immutable API image digest selected by the runtime overlay. The script waits for the migration to complete successfully, then applies the runtime overlay and waits for Worker, API and Web rollouts. It refuses to delete a still-active migration Job from a previous deployment.

The migration process uses the API image with `--migrate`, requires only the migration database connection and does not load the API HTTP listener certificate, OIDC configuration, broker credentials or worker mTLS listener. Production API replicas keep `Database__ApplyMigrations=false`.

## Production blockers

Static rendering is not an install/upgrade test. It does not prove that a selected CNI enforces NetworkPolicies, that the ingress controller handles client affinity and mTLS correctly, or that an external secret provider can rotate mounted credentials. Complete a disposable-cluster install/upgrade/uninstall, secret rotation, mTLS handshake/enrollment/revocation, load/chaos tests, independent penetration test, backup restore and measured RPO/RTO before public production exposure. Do not expose the worker directly to the public network.

## Environment-specific egress contract

## Customer-local worker connectivity

The base `sentinelai-api-worker` Service is currently a ClusterIP on TCP 8443 for the in-cluster Worker StatefulSet. A customer-local Worker outside Kubernetes cannot reach that DNS name. Before onboarding an external Worker, the selected provider/network owner must provision a private L4 TCP load balancer or TCP-passthrough proxy that forwards to this Service on port 8443 and preserves the TLS client certificate end-to-end. Point that Worker’s `Worker:ControlPlaneUrl` at the provider-issued reachable HTTPS endpoint. The endpoint certificate must cover that DNS name, and the API must still perform its CA-chain, EKU, thumbprint, tenant, identity and revocation checks.

Do not terminate worker mTLS at a generic HTTP ingress and do not trust caller-supplied certificate headers. Apply the narrowest feasible source CIDR allow-list, keep 8443 separate from the public user API ingress, and validate an actual external Worker registration/heartbeat/revocation flow from a customer-like network before production. No public worker endpoint is provisioned by these provider-neutral manifests.

The base NetworkPolicies deliberately use pod/namespace selectors for database and broker traffic. They allow PostgreSQL and RabbitMQ only to data-plane pods labelled in the operator-managed `sentinelai-data` namespace. The current staging/production hostnames in the ConfigMap are placeholders; do not assume that a managed database or broker reachable by a public/private DNS name is automatically permitted by these rules. For managed services outside the cluster, the selected provider/CNI overlay must add narrow endpoint CIDR rules or supported FQDN policy for the exact database and broker endpoints. Keep the default-deny policy, and do not broaden the worker's destination scope. Validate connectivity from each workload pod during staging.

## Shared Web authentication key ring

Production Web pods require the operator-provisioned `sentinelai-shared-rwx` StorageClass. It must provide an encrypted, durable `ReadWriteMany` volume. The base creates a 1 GiB PVC named `sentinelai-web-data-protection`; every Web replica mounts the same key-ring directory. The Web app validates that the directory is writable at startup and persists Data Protection keys there.

A separate ExternalSecret named `sentinelai-web-data-protection` mounts the current/previous PFX files and the PFX password. The current certificate encrypts new keys; current and previous certificates can decrypt existing keys during rotation. Keep every prior decryption certificate referenced by retained key-ring entries in the mounted secret until those entries can safely be retired. A certificate secret update must be followed by a controlled Web rollout because certificates are loaded at process startup.

The local overlay deletes the PVC and its Web volume/secret mounts; local Development uses the default local Data Protection behavior. No StorageClass, file service or encryption certificate is provisioned by these manifests. Verify concurrent access, file ownership, key creation, Web replica replacement and existing-cookie continuity in staging before treating the shared key ring as accepted.
