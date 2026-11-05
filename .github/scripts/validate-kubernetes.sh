#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
K8S_DIR="$ROOT_DIR/deploy/kubernetes"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required to render Kustomize overlays." >&2
  exit 1
fi
if ! command -v kubeconform >/dev/null 2>&1; then
  echo "kubeconform is required for Kubernetes schema validation." >&2
  exit 1
fi

for overlay in local staging production; do
  source_dir="$K8S_DIR/overlays/$overlay"
  rendered="$TEMP_DIR/$overlay.yaml"

  echo "::group::Render and validate $overlay overlay"
  kubectl kustomize "$source_dir" > "$rendered"
  test -s "$rendered"

  # Validate all built-in Kubernetes resources strictly. External Secrets Operator
  # resources are CRDs owned by the cluster add-on, so kubeconform skips only schemas
  # it does not know; the script separately asserts their expected API group and kind.
  kubeconform -strict -summary -ignore-missing-schemas "$rendered"

  if [[ "$overlay" != "local" ]]; then
    mapfile -t images < <(sed -nE 's/^[[:space:]]*image:[[:space:]]*([^[:space:]]+).*/\1/p' "$rendered")
    if [[ "${#images[@]}" -eq 0 ]]; then
      echo "$overlay overlay contains no container images." >&2
      exit 1
    fi
    for image in "${images[@]}"; do
      if [[ ! "$image" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "$overlay image is not pinned to a SHA-256 digest: $image" >&2
        exit 1
      fi
    done
    if grep -Eq '@sha256:0{64}$' "$rendered"; then
      echo "NOTICE: $overlay still contains placeholder image digests; it is not deployable until immutable release digests are promoted."
    fi

    if ! grep -q '^apiVersion: external-secrets.io/v1$' "$rendered" ||
       ! grep -q '^kind: ExternalSecret$' "$rendered"; then
      echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
      exit 1
    fi
  fi

  echo "Validated $overlay overlay."
  echo "::endgroup::"
done
