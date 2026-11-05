#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <provisioned-worker-identity> <private-output-directory>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
identity="$1"
output_dir="$2"

if [[ ! "$identity" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "Worker identity must be 1-128 characters using letters, digits, dot, underscore or hyphen." >&2
  exit 2
fi
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required." >&2; exit 1; }

mkdir -p "$output_dir"
chmod 700 "$output_dir"
key_file="$output_dir/$identity.key"
csr_file="$output_dir/$identity.csr"

if [[ -e "$key_file" || -e "$csr_file" ]]; then
  echo "Refusing to overwrite an existing key or CSR in '$output_dir'." >&2
  exit 1
fi

umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key_file"
chmod 600 "$key_file"

openssl req -new -sha256 -key "$key_file" -subj "/CN=$identity" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=critical,clientAuth" \
  -out "$csr_file"
chmod 600 "$csr_file"
openssl req -in "$csr_file" -noout -verify >/dev/null

echo "Created a worker private key and CSR."
echo "Private key: $key_file (keep on the worker; never upload or commit it)"
echo "CSR:         $csr_file (safe to send to your certificate authority)"
