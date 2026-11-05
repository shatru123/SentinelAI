# Kubernetes deployment

The supported local runtime remains Docker Compose. This directory contains the Phase 5 Kubernetes preparation manifests; these are not evidence of a completed or production-ready cluster deployment.

## Layout

- `base/`: API and Web Deployments, worker StatefulSet, services, ingress, service accounts, runtime ConfigMap, network policies, disruption/scaling and telemetry. The migration Job is intentionally separate from the runtime base.
- `overlays/local/`: Development-only local data services, local secrets and image tags.
- `overlays/staging/` and `overlays/production/`: runtime patches, replicas and External Secrets Operator resources.
- `overlays/{staging,production}/migration-prerequisites/`: namespace, service accounts, runtime configuration and external-secret references needed before migration.
- `overlays/{staging,production}/migration-job/`: the one-shot migration Job with its own promoted API image digest.

The staging and production overlays are templates. Their image digests, hostnames, OIDC issuer/client registration, trusted proxy addresses, bucket/KMS identifiers, worker IDs and tenant IDs must be replaced for the selected environment.

## Render and validate

From the repository root:

```bash
kubectl kustomize deploy/kubernetes/overlays/local
kubectl kustomize deploy/kubernetes/overlays/staging
kubectl kustomize deploy/kubernetes/overlays/production
kubectl kustomize deploy/kubernetes/overlays/staging/migration-prerequisites
kubectl kustomize deploy/kubernetes/overlays/staging/migration-job
kubectl kustomize deploy/kubernetes/overlays/production/migration-prerequisites
kubectl kustomize deploy/kubernetes/overlays/production/migration-job
bash .github/scripts/validate-kubernetes.sh
bash -n deploy/kubernetes/scripts/deploy.sh
```

CI installs checksum-verified versions of kubectl/Kustomize and kubeconform. Built-in Kubernetes schemas are validated strictly; External Secrets Operator resources are checked for their API group/kind but need the CRDs and a real ClusterSecretStore in the target cluster.

## Sequenced staging/production deployment

After replacing every template value and provisioning the target ClusterSecretStore, CA, identity provider, storage, registry and cluster networking out of band, deploy with an explicit context guard:

```bash
bash deploy/kubernetes/scripts/deploy.sh staging <expected-kubectl-context>
bash deploy/kubernetes/scripts/deploy.sh production <expected-kubectl-context>
```

The script refuses a mismatched context or unresolved placeholders. It applies the namespace/service accounts/configuration/ExternalSecrets first, waits until all ExternalSecrets are Ready, then runs the database-only migration Job and waits for completion. Only after the migration succeeds does it apply the runtime overlay and wait for Worker, API and Web rollouts. It refuses to delete a still-active migration Job from a previous deployment.

The migration process uses the API image with `--migrate`, requires only the migration database connection and does not load the API HTTP listener certificate, OIDC configuration, broker credentials or worker mTLS listener. Production API replicas keep `Database__ApplyMigrations=false`.

## Production blockers

Static rendering is not an install/upgrade test. It does not prove that a selected CNI enforces NetworkPolicies, that the ingress controller handles client affinity and mTLS correctly, or that an external secret provider can rotate mounted credentials. Complete a disposable-cluster install/upgrade/uninstall, secret rotation, mTLS handshake/enrollment/revocation, load/chaos tests, independent penetration test, backup restore and measured RPO/RTO before public production exposure. Do not expose the worker directly to the public network.
