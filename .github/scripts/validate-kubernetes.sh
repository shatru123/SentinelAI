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
      case "$image" in
        ghcr.io/shatru123/sentinelai-api*|ghcr.io/shatru123/sentinelai-web*|ghcr.io/shatru123/sentinelai-worker*)
          if [[ ! "$image" =~ @sha256:[0-9a-f]{64}$ ]]; then
            echo "$overlay first-party image must be pinned to a SHA-256 digest: $image" >&2
            exit 1
          fi
          ;;
        *)
          # Third-party runtime images must use an explicit release tag or digest.
          # Reject floating aliases such as latest and untagged repository references.
          if [[ "$image" == *:latest || "$image" != *@sha256:* && "$image" != *:* ]]; then
            echo "$overlay third-party image must use an explicit version tag or digest: $image" >&2
            exit 1
          fi
          ;;
      esac
    done
    if grep -Eq '@sha256:0{64}$' "$rendered"; then
      echo "NOTICE: $overlay still contains placeholder image digests; it is not deployable until immutable release digests are promoted."
    fi

    # Production-like overlays must not put secret values in ConfigMaps.
    # Secret references belong in ExternalSecret resources and Pod secretKeyRef entries.
    if grep -Eq '^[[:space:]]+[A-Za-z0-9_.-]*(Password|Secret|Token|PrivateKey):' "$rendered"; then
      echo "$overlay rendered a secret-like configuration key; move the value to the external secret provider." >&2
      grep -En '^[[:space:]]+[A-Za-z0-9_.-]*(Password|Secret|Token|PrivateKey):' "$rendered" >&2
      exit 1
    fi

    if ! grep -q '^apiVersion: external-secrets.io/v1  fi

  echo "Validated $overlay overlay."
  echo "::endgroup::"
done
 "$rendered" ||
       ! grep -q '^kind: ExternalSecret  fi

  echo "Validated $overlay overlay."
  echo "::endgroup::"
done
 "$rendered"; then
      echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
      exit 1
    fi
  fi

  echo "Validated $overlay overlay."
  echo "::endgroup::"
done
