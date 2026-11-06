#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <staging|production> <api-sha256> <web-sha256> <worker-sha256>" >&2
  exit 2
}

[[ $# -eq 4 ]] || usage
environment="$1"
api_digest="$2"
web_digest="$3"
worker_digest="$4"

case "$environment" in
  staging|production) ;;
  *) usage ;;
esac

for digest in "$api_digest" "$web_digest" "$worker_digest"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Every image digest must be exactly 64 lowercase hexadecimal characters (without the sha256: prefix)." >&2
    exit 2
  }
done

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
K8S_DIR="${SENTINELAI_K8S_DIR:-$ROOT_DIR/deploy/kubernetes}"
OVERLAY_DIR="$K8S_DIR/overlays/$environment"
KUSTOMIZATION="$OVERLAY_DIR/kustomization.yaml"

command -v kubectl >/dev/null 2>&1 || {
  echo "kubectl is required to validate the promoted overlay." >&2
  exit 1
}
[[ -f "$KUSTOMIZATION" ]] || {
  echo "Missing Kustomize overlay: $KUSTOMIZATION" >&2
  exit 1
}

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
BACKUP="$TEMP_DIR/kustomization.yaml"
cp "$KUSTOMIZATION" "$BACKUP"

if ! awk \
  -v api="$api_digest" \
  -v web="$web_digest" \
  -v worker="$worker_digest" '
  /^[[:space:]]*-[[:space:]]+name:/ { current = $3 }
  /^[[:space:]]+digest:/ {
    if (current == "ghcr.io/shatru123/sentinelai-api") {
      sub(/digest:.*/, "digest: sha256:" api)
      api_seen = 1
    } else if (current == "ghcr.io/shatru123/sentinelai-web") {
      sub(/digest:.*/, "digest: sha256:" web)
      web_seen = 1
    } else if (current == "ghcr.io/shatru123/sentinelai-worker") {
      sub(/digest:.*/, "digest: sha256:" worker)
      worker_seen = 1
    }
    current = ""
  }
  { print }
  END { if (!api_seen || !web_seen || !worker_seen) exit 3 }
' "$KUSTOMIZATION" > "$TEMP_DIR/kustomization.yaml"; then
  echo "Overlay must contain API, Web and Worker image digest entries." >&2
  exit 1
fi

install -m 0644 "$TEMP_DIR/kustomization.yaml" "$KUSTOMIZATION"
if ! kubectl kustomize "$OVERLAY_DIR" > "$TEMP_DIR/rendered.yaml"; then
  cp "$BACKUP" "$KUSTOMIZATION"
  echo "Promoted overlay failed Kustomize rendering; original file restored." >&2
  exit 1
fi

for image in api web worker; do
  digest_var="${image^^}_DIGEST"
  expected="${!digest_var}"
  if ! grep -Fq "image: ghcr.io/shatru123/sentinelai-${image}@sha256:${expected}" "$TEMP_DIR/rendered.yaml"; then
    cp "$BACKUP" "$KUSTOMIZATION"
    echo "Rendered $environment overlay did not contain the expected $image digest; original file restored." >&2
    exit 1
  fi
done

echo "Pinned API, Web and Worker to immutable SHA-256 digests in the $environment overlay."
echo "No cluster resources were changed. Review and commit the overlay before deployment."
