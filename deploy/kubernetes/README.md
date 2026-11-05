# Kubernetes deployment

The supported local runtime remains Docker Compose. This directory contains the Phase 5 Kubernetes preparation manifests; these are not evidence of a completed or production-ready cluster deployment.

## Layout

- `base/`: API and Web Deployments, worker StatefulSet, services, ingress, service accounts, runtime ConfigMap, migration Job, network policies, disruption/scaling and telemetry resources.
- `overlays/local/`: Development-only local data services, local secrets and image tags.
- `overlays/staging/` and `overlays/production/`: environment-specific runtime patches and External Secrets Operator resources. The image digests and environment identifiers are placeholders.

## Render and validate

From the repository root:

```bash
kubectl kustomize deploy/kubernetes/overlays/local
kubectl kustomize deploy/kubernetes/overlays/staging
kubectl kustomize deploy/kubernetes/overlays/production
bash .github/scripts/validate-kubernetes.sh
```

CI installs a pinned kubeconform release and runs this script. Built-in Kubernetes schemas are validated strictly; External Secrets Operator resources are recognized by their API group/kind but require the CRDs and a real ClusterSecretStore in the target cluster.

## Production blockers

Do not apply staging or production overlays until the example hostnames, OIDC configuration, trusted proxy IPs, S3 bucket/KMS IDs, provisioned tenant and worker identity, image digests and secret-store configuration are replaced with real environment values. Create secret values and workload identity out of band. Validate the ingress controller, TLS chain, mTLS client-certificate forwarding, network policies on the selected CNI, external secret refresh and migration sequencing in a disposable/staging cluster first.

The one-shot migration Job uses `--migrate` and requires only the migration database configuration. API replicas must not apply migrations automatically. No production provider, account or region is selected here. Do not expose the worker directly to the public network.
