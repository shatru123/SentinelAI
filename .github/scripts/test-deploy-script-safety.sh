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

echo "Deployment safety checks passed: wrong context and placeholders both fail closed."
