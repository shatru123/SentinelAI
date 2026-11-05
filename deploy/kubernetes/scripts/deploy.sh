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
OVERLAY_DIR="$ROOT_DIR/deploy/kubernetes/overlays/$environment"
PREREQUISITES="$OVERLAY_DIR/migration-prerequisites"
MIGRATION_JOB="$OVERLAY_DIR/migration-job"

for directory in "$PREREQUISITES" "$MIGRATION_JOB" "$OVERLAY_DIR"; do
  rendered="$(kubectl kustomize "$directory")"
  if grep -Eq 'example\.invalid|replace-me|placeholder|sha256:0{64}' <<< "$rendered"; then
    echo "Refusing deployment: '$directory' still contains environment or image placeholders." >&2
    exit 1
  fi
done

kubectl get crd externalsecrets.external-secrets.io >/dev/null

echo "Applying namespace, service accounts, runtime configuration and external secret references."
kubectl apply -k "$PREREQUISITES"

echo "Waiting for all external secrets to synchronize before migration."
kubectl wait --for=condition=Ready externalsecrets.external-secrets.io \
  --all --namespace sentinelai --timeout=300s

echo "Replacing any completed migration Job from a previous release."
kubectl delete job sentinelai-migrate --namespace sentinelai --ignore-not-found=true --wait=true

echo "Running the one-shot schema migration."
kubectl apply -k "$MIGRATION_JOB"
kubectl wait --for=condition=Complete job/sentinelai-migrate \
  --namespace sentinelai --timeout=900s

echo "Database migration completed. Applying API, Web, Worker and supporting services."
kubectl apply -k "$OVERLAY_DIR"

echo "Waiting for Worker, API and Web rollouts."
kubectl rollout status statefulset/sentinelai-worker --namespace sentinelai --timeout=900s
kubectl rollout status deployment/sentinelai-api --namespace sentinelai --timeout=900s
kubectl rollout status deployment/sentinelai-web --namespace sentinelai --timeout=900s

echo "SentinelAI $environment rollout completed successfully in context '$actual_context'."
