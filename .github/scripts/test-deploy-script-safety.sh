#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/kubernetes/scripts/deploy.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
BIN_DIR="$TEMP_DIR/bin"
mkdir -p "$BIN_DIR"

cat > "$BIN_DIR/kubectl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >> "$KUBECTL_CALL_LOG"
if [[ "$1" == "config" && "$2" == "current-context" ]]; then
  printf '%s\n' "${FAKE_KUBECTL_CONTEXT:-phase5-test}"
  exit 0
fi
if [[ "$1" == "kustomize" ]]; then
  printf '%s\n' "${FAKE_KUSTOMIZE_OUTPUT:-host: api.example.invalid}"
  exit 0
fi
echo "Unexpected kubectl call in safety test: $*" >&2
exit 97
STUB
chmod +x "$BIN_DIR/kubectl"

export PATH="$BIN_DIR:$PATH"
export KUBECTL_CALL_LOG="$TEMP_DIR/kubectl.log"

# A context mismatch must stop before rendering or mutation.
set +e
FAKE_KUBECTL_CONTEXT="production-context" bash "$DEPLOY_SCRIPT" staging "different-context" >"$TEMP_DIR/context.out" 2>&1
context_status=$?
set -e
if [[ "$context_status" -eq 0 ]] || ! grep -Fq "does not match expected context" "$TEMP_DIR/context.out"; then
  echo "Deployment did not reject a mismatched kubectl context." >&2
  cat "$TEMP_DIR/context.out" >&2
  exit 1
fi
if grep -Eq '^(apply|delete|patch|scale)( |$)' "$KUBECTL_CALL_LOG" 2>/dev/null; then
  echo "Deployment attempted a mutation after a context mismatch." >&2
  cat "$KUBECTL_CALL_LOG" >&2
  exit 1
fi

# A correct context with unresolved placeholders must also stop before mutation.
: > "$KUBECTL_CALL_LOG"
set +e
FAKE_KUBECTL_CONTEXT="staging-context" \
FAKE_KUSTOMIZE_OUTPUT="host: api.example.invalid" \
  bash "$DEPLOY_SCRIPT" staging "staging-context" >"$TEMP_DIR/placeholder.out" 2>&1
placeholder_status=$?
set -e
if [[ "$placeholder_status" -eq 0 ]] || ! grep -Fq "still contains environment or image placeholders" "$TEMP_DIR/placeholder.out"; then
  echo "Deployment did not reject unresolved environment placeholders." >&2
  cat "$TEMP_DIR/placeholder.out" >&2
  exit 1
fi
if grep -Eq '^(apply|delete|patch|scale)( |$)' "$KUBECTL_CALL_LOG"; then
  echo "Deployment attempted a mutation before placeholder validation passed." >&2
  cat "$KUBECTL_CALL_LOG" >&2
  exit 1
fi

# Even a placeholder-free overlay must stop before cluster mutation when
# the first-party image signature cannot be verified.
cat > "$BIN_DIR/cosign" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\\n' "$*" >> "$COSIGN_CALL_LOG"
exit 42
STUB
chmod +x "$BIN_DIR/cosign"
export COSIGN_CALL_LOG="$TEMP_DIR/cosign.log"
: > "$KUBECTL_CALL_LOG"
cat > "$TEMP_DIR/signed-images.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinelai-api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/shatru123/sentinelai-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinelai-web
spec:
  template:
    spec:
      containers:
        - name: web
          image: ghcr.io/shatru123/sentinelai-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sentinelai-worker
spec:
  template:
    spec:
      containers:
        - name: worker
          image: ghcr.io/shatru123/sentinelai-worker@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
YAML
set +e
FAKE_KUBECTL_CONTEXT="staging-context" \
FAKE_KUSTOMIZE_OUTPUT="$(cat "$TEMP_DIR/signed-images.yaml")" \
  bash "$DEPLOY_SCRIPT" staging "staging-context" >"$TEMP_DIR/signature.out" 2>&1
signature_status=$?
set -e
if [[ "$signature_status" -eq 0 ]] || ! grep -Fq "signature verification failed for api image" "$TEMP_DIR/signature.out"; then
  echo "Deployment did not reject an unverified image signature." >&2
  cat "$TEMP_DIR/signature.out" >&2
  exit 1
fi
grep -Fq "sentinelai-api@" "$COSIGN_CALL_LOG"
if grep -Eq '^(apply|delete|patch|scale)( |$)' "$KUBECTL_CALL_LOG"; then
  echo "Deployment attempted a mutation before image signature verification passed." >&2
  cat "$KUBECTL_CALL_LOG" >&2
  exit 1
fi

echo "Deployment safety checks passed: context, placeholders and unsigned images all fail closed."
