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

validate_overlay() {
  local overlay="$1"
  local source_dir="$K8S_DIR/overlays/$overlay"
  local label="${overlay//\//-}"
  local rendered="$TEMP_DIR/$label.yaml"

  echo "::group::Render and validate $overlay"
  kubectl kustomize "$source_dir" > "$rendered"
  test -s "$rendered"

  # Validate built-in Kubernetes resources. External Secrets Operator owns its CRDs;
  # their API group and kind are checked below and the live CRDs are a cluster gate.
  kubeconform -strict -summary -ignore-missing-schemas "$rendered"

  if [[ "$overlay" != "local" ]]; then
    # Only runtime and migration-job overlays contain images. First-party release
    # images must be digest pinned; third-party images must use an explicit version.
    if [[ "$overlay" != */migration-prerequisites ]]; then
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
            if [[ "$image" != *@sha256:* ]]; then
              local image_name="${image##*/}"
              if [[ "$image_name" != *:* || "${image_name##*:}" == "latest" ]]; then
                echo "$overlay third-party image must use an explicit version tag or digest: $image" >&2
                exit 1
              fi
            fi
            ;;
        esac
      done

      if grep -Eq '@sha256:0{64}$' "$rendered"; then
        echo "NOTICE: $overlay still contains placeholder image digests; it is not deployable until immutable release digests are promoted."
      fi
    fi

    # Production-like overlays must not place password, token, secret or private-key
    # values in plain manifest data. Workload secretKeyRef and ExternalSecret references
    # remain allowed because they reference provider-managed values.
    secret_like_keys="$(grep -En '^[[:space:]]+[A-Za-z0-9_.-]*(Password|Secret|Token|PrivateKey):' "$rendered" \
      | grep -Ev '^[0-9]+:[[:space:]]*automountServiceAccountToken:' || true)"
    if [[ -n "$secret_like_keys" ]]; then
      echo "$overlay rendered a secret-like configuration key; move the value to the external secret provider." >&2
      echo "$secret_like_keys" >&2
      exit 1
    fi

    if ! grep -q '^  HTTPS_PROXY: http://sentinelai-egress-gateway.sentinelai-operations.svc.cluster.local:443    if [[ "$overlay" != */migration-job ]]; then
      if ! grep -q '^apiVersion: external-secrets.io/v1$' "$rendered" ||
         ! grep -q '^kind: ExternalSecret$' "$rendered"; then
        echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
        exit 1
      fi
    fi
  fi

  echo "Validated $overlay."
  echo "::endgroup::"
}

for overlay in local staging production; do
  validate_overlay "$overlay"
done

echo "::group::Validate the standalone one-shot migration Job"
kubeconform -strict -summary -ignore-missing-schemas "$K8S_DIR/base/migration-job.yaml"
echo "::endgroup::"

bash -n "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"
 "$rendered" ||
       ! grep -q '^  NO_PROXY:' "$rendered" ||
       ! grep -q '^  name: web-egress    if [[ "$overlay" != */migration-job ]]; then
      if ! grep -q '^apiVersion: external-secrets.io/v1$' "$rendered" ||
         ! grep -q '^kind: ExternalSecret$' "$rendered"; then
        echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
        exit 1
      fi
    fi
  fi

  echo "Validated $overlay."
  echo "::endgroup::"
}

for overlay in local staging production; do
  validate_overlay "$overlay"
done

echo "::group::Validate the standalone one-shot migration Job"
kubeconform -strict -summary -ignore-missing-schemas "$K8S_DIR/base/migration-job.yaml"
echo "::endgroup::"

bash -n "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"
 "$rendered" ||
       ! grep -q 'app.kubernetes.io/name: sentinelai-egress-gateway' "$rendered"; then
      echo "$overlay must route Web outbound requests through the restricted operations egress gateway and bypass only cluster-local services." >&2
      exit 1
    fi

    if [[ "$overlay" != */migration-job ]]; then
      if ! grep -q '^apiVersion: external-secrets.io/v1$' "$rendered" ||
         ! grep -q '^kind: ExternalSecret$' "$rendered"; then
        echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
        exit 1
      fi
    fi
  fi

  echo "Validated $overlay."
  echo "::endgroup::"
}

for overlay in local staging production; do
  validate_overlay "$overlay"
done

echo "::group::Validate the standalone one-shot migration Job"
kubeconform -strict -summary -ignore-missing-schemas "$K8S_DIR/base/migration-job.yaml"
echo "::endgroup::"

bash -n "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"
