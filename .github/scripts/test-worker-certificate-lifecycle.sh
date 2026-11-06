#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CSR_SCRIPT="$ROOT_DIR/deploy/certificates/create-worker-csr.sh"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/certificates/package-worker-certificate.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
chmod 700 "$TEMP_DIR"

if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required for the worker certificate lifecycle test." >&2
  exit 1
fi

worker_dir="$TEMP_DIR/worker"
bash "$CSR_SCRIPT" worker-ci-01 "$worker_dir"
key_file="$worker_dir/worker-ci-01.key"
csr_file="$worker_dir/worker-ci-01.csr"
[[ -s "$key_file" && -s "$csr_file" ]]
[[ "$(stat -c '%a' "$key_file")" == "600" ]]
[[ "$(stat -c '%a' "$worker_dir")" == "700" ]]
openssl req -in "$csr_file" -noout -verify >/dev/null

# Create a short-lived test CA and sign the CSR while preserving the requested EKU.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEMP_DIR/ca.key"
chmod 600 "$TEMP_DIR/ca.key"
openssl req -x509 -new -sha256 -key "$TEMP_DIR/ca.key" -days 365 \
  -subj "/CN=SentinelAI Test Worker CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$TEMP_DIR/ca.crt"
openssl x509 -req -in "$csr_file" -CA "$TEMP_DIR/ca.crt" -CAkey "$TEMP_DIR/ca.key" \
  -CAcreateserial -days 30 -sha256 -copy_extensions copy \
  -out "$TEMP_DIR/worker-ci-01.crt"

# A mismatched worker identity must fail before a PFX is created.
set +e
printf 'not-used-password\nnot-used-password\n' |
  bash "$PACKAGE_SCRIPT" another-worker "$key_file" "$TEMP_DIR/worker-ci-01.crt" \
    "$TEMP_DIR/ca.crt" "$TEMP_DIR/should-not-exist.pfx" \
    >"$TEMP_DIR/negative.out" 2>&1
negative_status=$?
set -e
if [[ "$negative_status" -eq 0 || -e "$TEMP_DIR/should-not-exist.pfx" ]]; then
  echo "Certificate packaging accepted a mismatched worker identity." >&2
  cat "$TEMP_DIR/negative.out" >&2
  exit 1
fi

printf 'test-worker-pfx-password\ntest-worker-pfx-password\n' |
  bash "$PACKAGE_SCRIPT" worker-ci-01 "$key_file" "$TEMP_DIR/worker-ci-01.crt" \
    "$TEMP_DIR/ca.crt" "$worker_dir/worker-ci-01.pfx"

pfx_file="$worker_dir/worker-ci-01.pfx"
[[ -s "$pfx_file" ]]
[[ "$(stat -c '%a' "$pfx_file")" == "600" ]]
openssl pkcs12 -in "$pfx_file" -noout -passin pass:test-worker-pfx-password
openssl pkcs12 -in "$pfx_file" -nocerts -noout -passin pass:test-worker-pfx-password

echo "Worker certificate lifecycle checks passed: local key, CSR, CA validation, identity binding and PFX packaging."
