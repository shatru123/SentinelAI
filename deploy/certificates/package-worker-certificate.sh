#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <worker-identity> <private-key.pem> <signed-client-cert.pem> <trusted-root-ca.pem> <output.pfx> [intermediate-chain.pem]" >&2
  exit 2
}

[[ $# -ge 5 && $# -le 6 ]] || usage
identity="$1"
key_file="$2"
certificate_file="$3"
root_ca_file="$4"
output_file="$5"
intermediate_file="${6:-}"

if [[ ! "$identity" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "Invalid worker identity." >&2
  exit 2
fi
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required." >&2; exit 1; }
for file in "$key_file" "$certificate_file" "$root_ca_file"; do
  [[ -s "$file" && -r "$file" ]] || { echo "Required input is missing or unreadable: $file" >&2; exit 1; }
done
if [[ -n "$intermediate_file" && ! -s "$intermediate_file" ]]; then
  echo "Intermediate certificate chain is missing or empty: $intermediate_file" >&2
  exit 1
fi
if [[ -e "$output_file" ]]; then
  echo "Refusing to overwrite existing PKCS#12 output: $output_file" >&2
  exit 1
fi

subject="$(openssl x509 -in "$certificate_file" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
if ! printf '%s\n' "$subject" | tr ',' '\n' | grep -Fxq "CN=$identity"; then
  echo "The signed certificate subject does not contain the provisioned worker identity '$identity'." >&2
  exit 1
fi
if ! openssl x509 -in "$certificate_file" -purpose -noout | grep -Fxq "SSL client : Yes"; then
  echo "The certificate is not valid for TLS client authentication." >&2
  exit 1
fi

verify_args=(-purpose sslclient -CAfile "$root_ca_file")
if [[ -n "$intermediate_file" ]]; then
  verify_args+=(-untrusted "$intermediate_file")
fi
openssl verify "${verify_args[@]}" "$certificate_file"

certificate_public_key="$(
  openssl x509 -in "$certificate_file" -pubkey -noout |
    openssl pkey -pubin -outform DER |
    openssl dgst -sha256
)"
private_public_key="$(
  openssl pkey -in "$key_file" -pubout -outform DER |
    openssl dgst -sha256
)"
if [[ "$certificate_public_key" != "$private_public_key" ]]; then
  echo "The signed certificate does not match the supplied private key." >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output_file")"
chmod 700 "$(dirname -- "$output_file")"
umask 077

read -r -s -p "PKCS#12 password (use at least 16 characters): " password
printf '\n'
read -r -s -p "Confirm PKCS#12 password: " confirmation
printf '\n'
if [[ ${#password} -lt 16 || "$password" != "$confirmation" ]]; then
  unset password confirmation
  echo "Passwords must match and contain at least 16 characters." >&2
  exit 1
fi

cleanup_on_error() {
  rm -f -- "$output_file"
}
trap cleanup_on_error ERR

exec 3<<<"$password"
if [[ -n "$intermediate_file" ]]; then
  openssl pkcs12 -export -inkey "$key_file" -in "$certificate_file" \
    -certfile "$intermediate_file" -out "$output_file" -passout fd:3
else
  openssl pkcs12 -export -inkey "$key_file" -in "$certificate_file" \
    -out "$output_file" -passout fd:3
fi
exec 3<&-
unset password confirmation
chmod 600 "$output_file"
trap - ERR

echo "Created a PKCS#12 client certificate bundle: $output_file"
echo "The private key remains local. Store this PFX and its password in the worker's secret manager."
