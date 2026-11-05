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

    local secret_like_keys
    secret_like_keys="$(grep -En '^[[:space:]]+[-A-Za-z0-9_.]*(Password|Secret|Token|PrivateKey):' "$rendered" \
      | grep -Ev '^[0-9]+:[[:space:]]*automountServiceAccountToken:' || true)"
    if [[ -n "$secret_like_keys" ]]; then
      echo "$overlay rendered a secret-like configuration key; move the value to the external secret provider." >&2
      echo "$secret_like_keys" >&2
      exit 1
    fi

    if ! grep -Fq 'HTTPS_PROXY: http://sentinelai-egress-gateway.sentinelai-operations.svc.cluster.local:443' "$rendered" ||
       ! grep -Fq 'NO_PROXY:' "$rendered" ||
       ! grep -Fq 'name: web-egress' "$rendered" ||
       ! grep -Fq 'app.kubernetes.io/name: sentinelai-egress-gateway' "$rendered"; then
      echo "$overlay must route Web outbound requests through the restricted operations egress gateway and bypass only cluster-local services." >&2
      exit 1
    fi

    if ! grep -Fq 'apiVersion: external-secrets.io/v1' "$rendered" ||
       ! grep -Fq 'kind: ExternalSecret' "$rendered"; then
      echo "$overlay must render ExternalSecret resources using external-secrets.io/v1." >&2
      exit 1
    fi

    if ! grep -Fq 'ReadWriteMany' "$rendered" ||
       ! grep -Fq 'DataProtection__KeyRingPath: /var/lib/sentinelai-data-protection' "$rendered" ||
       ! grep -Fq 'DataProtection__CertificatePath: /var/run/sentinelai-web-data-protection/current.pfx' "$rendered" ||
       ! grep -Fq 'DataProtection__PreviousCertificatePaths__0: /var/run/sentinelai-web-data-protection/previous.pfx' "$rendered" ||
       ! grep -Fq 'secretKey: current.pfx' "$rendered" ||
       ! grep -Fq 'secretKey: previous.pfx' "$rendered" ||
       ! grep -Fq 'secretKey: password' "$rendered"; then
      echo "$overlay must provide the shared RWX encrypted Web Data Protection key ring and current/previous certificate secrets." >&2
      exit 1
    fi
  fi

  echo "Validated $overlay."
  echo "::endgroup::"
}

for overlay in local staging production; do
  validate_overlay "$overlay"
done

LOCAL_RENDERED="$TEMP_DIR/local.yaml"
if grep -Eq 'claimName: sentinelai-web-data-protection|secretName: sentinelai-web-data-protection|name: data-protection-key-ring|name: data-protection-certificate' "$LOCAL_RENDERED"; then
  echo "Local Development overlay must not require Production Data Protection PVC/certificate secrets." >&2
  exit 1
fi

if ! grep -Fq "ReadWriteMany" "$K8S_DIR/base/data-protection-storage.yaml" ||
   ! grep -Fq "kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/sentinelai-web-data-protection" "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh" ||
   ! grep -Fq "kubectl get storageclass sentinelai-shared-rwx" "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"; then
  echo "Production deploy must require a provisioned shared RWX StorageClass and wait for the Data Protection PVC to bind." >&2
  exit 1
fi

echo "::group::Validate the standalone one-shot migration Job"
kubeconform -strict -summary -ignore-missing-schemas "$K8S_DIR/base/migration-job.yaml"
echo "::endgroup::"

bash -n "$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"
bash "$ROOT_DIR/.github/scripts/test-deploy-script-safety.sh"
