#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <staging|production> <expected-kubectl-context>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
environment="$1"
expected_context="$2"

case "$environment" in
  staging|production) ;;
  *) usage ;;
esac

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required." >&2
  exit 1
fi

actual_context="$(kubectl config current-context)"
if [[ "$actual_context" != "$expected_context" ]]; then
  echo "Refusing deployment: current context '$actual_context' does not match expected context '$expected_context'." >&2
  exit 1
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
K8S_DIR="$ROOT_DIR/deploy/kubernetes"
OVERLAY_DIR="$K8S_DIR/overlays/$environment"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Validate the exact runtime overlay and its first-party image digests before
# creating or changing any cluster resources.
RUNTIME_MANIFEST="$TEMP_DIR/runtime.yaml"
kubectl kustomize "$OVERLAY_DIR" > "$RUNTIME_MANIFEST"
if grep -Eq 'example\.invalid|replace-me|placeholder|sha256:0{64}|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|staging-worker-east-01|production-worker-east-01' "$RUNTIME_MANIFEST"; then
  echo "Refusing deployment: the $environment overlay still contains environment or image placeholders." >&2
  exit 1
fi

extract_image() {
  local component="$1"
  awk -v name="sentinelai-$component" '
    /^kind: (Deployment|StatefulSet)$/ { workload=1; matched=0; next }
    workload && /^[[:space:]]*name:/ && $2 == name { matched=1; next }
    matched && /^[[:space:]]*image:/ {
      sub(/^[[:space:]]*image:[[:space:]]*/, "")
      print
      exit
    }
    /^---$/ { workload=0; matched=0 }
  ' "$RUNTIME_MANIFEST"
}

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify signed API, Web and Worker images." >&2
  exit 1
fi

identity_regex='^https://github.com/shatru123/SentinelAI/.github/workflows/release-images.yml@refs/'
for component in api web worker; do
  image="$(extract_image "$component")"
  if [[ ! "$image" =~ ^ghcr\.io/shatru123/sentinelai-$component@sha256:[0-9a-f]{64}$ ]]; then
    echo "Refusing deployment: the $component image is not the expected immutable GHCR digest." >&2
    exit 1
  fi

  echo "Verifying the GitHub OIDC signature for $component image."
  if ! cosign verify --certificate-identity-regexp "$identity_regex" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" "$image" \
      > "$TEMP_DIR/$component-signature.json"; then
    echo "Refusing deployment: signature verification failed for $component image." >&2
    exit 1
  fi
done

# The one-shot migration Job must use the same immutable API image digest
# selected and signature-verified for the runtime rollout.
api_image="$(extract_image api)"
if [[ -z "$api_image" ]]; then
  echo "Refusing deployment: the signed API image could not be extracted from the runtime overlay." >&2
  exit 1
fi

kubectl get crd externalsecrets.external-secrets.io >/dev/null
if ! kubectl get storageclass sentinelai-shared-rwx >/dev/null 2>&1; then
  echo "Refusing deployment: the operator must provision the sentinelai-shared-rwx ReadWriteMany StorageClass first." >&2
  exit 1
fi

echo "Applying namespace, service accounts and base runtime configuration."
kubectl apply -f "$K8S_DIR/base/namespace.yaml"
kubectl apply -f "$K8S_DIR/base/service-accounts.yaml"
kubectl apply -f "$K8S_DIR/base/configmap.yaml"

echo "Applying $environment external secret references and runtime overrides."
kubectl apply -f "$OVERLAY_DIR/external-secrets.yaml"
kubectl patch configmap sentinelai-runtime --namespace sentinelai \
  --type merge --patch-file "$OVERLAY_DIR/runtime-patch.yaml"

echo "Waiting for all external secrets to synchronize before migration."
kubectl wait --for=condition=Ready externalsecrets.external-secrets.io \
  --all --namespace sentinelai --timeout=300s

echo "Checking whether a migration Job from a previous release is still active."
if kubectl get job sentinelai-migrate --namespace sentinelai >/dev/null 2>&1; then
  active_jobs="$(kubectl get job sentinelai-migrate --namespace sentinelai -o jsonpath='{.status.active}' 2>/dev/null || true)"
  if [[ -n "$active_jobs" && "$active_jobs" != "0" ]]; then
    echo "Refusing deployment because the previous migration Job is still active." >&2
    exit 1
  fi
  kubectl delete job sentinelai-migrate --namespace sentinelai --wait=true
fi

echo "Preparing the migration Job with the exact API image digest selected by the runtime overlay."
sed -E "s#^([[:space:]]*image:)[[:space:]]*.*#\1 $api_image#" \
  "$K8S_DIR/base/migration-job.yaml" > "$TEMP_DIR/migration-job.yaml"
if ! grep -Fq "image: $api_image" "$TEMP_DIR/migration-job.yaml"; then
  echo "Could not set the migration Job image to the promoted API digest." >&2
  exit 1
fi

echo "Running the one-shot schema migration before changing application workloads."
kubectl apply -f "$TEMP_DIR/migration-job.yaml"
kubectl wait --for=condition=Complete job/sentinelai-migrate \
  --namespace sentinelai --timeout=900s

echo "Database migration completed. Applying API, Web, Worker and supporting services."
kubectl apply -k "$OVERLAY_DIR"

echo "Waiting for the shared ReadWriteMany Web Data Protection key-ring volume."
kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/sentinelai-web-data-protection \
  --namespace sentinelai --timeout=300s

echo "Waiting for Worker, API and Web rollouts."
kubectl rollout status statefulset/sentinelai-worker --namespace sentinelai --timeout=900s
kubectl rollout status deployment/sentinelai-api --namespace sentinelai --timeout=900s
# Reload the Web process after ExternalSecret synchronization so current/previous
# Data Protection certificates are loaded even when the Deployment image is unchanged.
kubectl rollout restart deployment/sentinelai-web --namespace sentinelai
kubectl rollout status deployment/sentinelai-web --namespace sentinelai --timeout=900s

echo "SentinelAI $environment rollout completed successfully in context '$actual_context'."
