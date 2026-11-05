# Kubernetes deployment

The supported local runtime remains Docker Compose. This directory contains the Phase 5 Kubernetes preparation manifests; these are not evidence of a completed or production-ready cluster deployment.

## Layout

- `base/`: API and Web Deployments, worker StatefulSet, services, ingress, service accounts, runtime ConfigMap, network policies, disruption/scaling and telemetry. The one-shot migration Job is kept separate from the runtime base.
- `overlays/local/`: Development-only local data services, local secrets and image tags.
- `overlays/staging/` and `overlays/production/`: environment-specific runtime patches, replica counts and External Secrets Operator resources.
- `scripts/deploy.sh`: context-guarded release sequence for staging and production.

Staging and production remain templates. Their image digests, hostnames, OIDC issuer/client registration, trusted proxy addresses, bucket/KMS identifiers, worker IDs and tenant IDs must be replaced for the selected environment.

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
