#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_K8S_DIR="$ROOT_DIR/deploy/kubernetes"
PROMOTE_SCRIPT="$ROOT_DIR/deploy/kubernetes/scripts/promote-image-digests.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
TEST_K8S_DIR="$TEMP_DIR/kubernetes"
cp -R "$SOURCE_K8S_DIR" "$TEST_K8S_DIR"

staging_file="$TEST_K8S_DIR/overlays/staging/kustomization.yaml"
production_file="$TEST_K8S_DIR/overlays/production/kustomization.yaml"
cp "$staging_file" "$TEMP_DIR/staging-before.yaml"
cp "$production_file" "$TEMP_DIR/production-before.yaml"

# Invalid digests must fail before modifying the selected environment overlay.
set +e
SENTINELAI_K8S_DIR="$TEST_K8S_DIR" bash "$PROMOTE_SCRIPT" staging invalid "$(printf 'b%.0s' {1..64})" "$(printf 'c%.0s' {1..64})" >"$TEMP_DIR/invalid.out" 2>&1
invalid_status=$?
set -e
if [[ "$invalid_status" -eq 0 ]] || ! cmp -s "$staging_file" "$TEMP_DIR/staging-before.yaml"; then
  echo "Digest promotion did not fail closed for an invalid digest." >&2
  cat "$TEMP_DIR/invalid.out" >&2
  exit 1
fi

api="$(printf 'a%.0s' {1..64})"
web="$(printf 'b%.0s' {1..64})"
worker="$(printf 'c%.0s' {1..64})"
SENTINELAI_K8S_DIR="$TEST_K8S_DIR" bash "$PROMOTE_SCRIPT" staging "$api" "$web" "$worker"

kubectl kustomize "$TEST_K8S_DIR/overlays/staging" > "$TEMP_DIR/staging-rendered.yaml"
grep -Fq "image: ghcr.io/shatru123/sentinelai-api@sha256:$api" "$TEMP_DIR/staging-rendered.yaml"
grep -Fq "image: ghcr.io/shatru123/sentinelai-web@sha256:$web" "$TEMP_DIR/staging-rendered.yaml"
grep -Fq "image: ghcr.io/shatru123/sentinelai-worker@sha256:$worker" "$TEMP_DIR/staging-rendered.yaml"
cmp -s "$production_file" "$TEMP_DIR/production-before.yaml"

echo "Image promotion checks passed: invalid digests fail closed, staging uses exact digests, production remains unchanged."
