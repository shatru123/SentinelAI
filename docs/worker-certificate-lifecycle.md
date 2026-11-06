# Worker certificate lifecycle

This procedure is the supported manual bootstrap and rotation path for the Phase 5 mTLS worker identity. It uses a customer-controlled or organization-controlled CA. SentinelAI validates a signed public certificate; it never receives or generates the worker's private key.

## Identity and trust requirements

- Provision the worker through the SentinelAI Admin workflow first. The worker identity and tenant are authoritative records; a worker cannot create its own identity, tenant or capabilities.
- The certificate subject Common Name must exactly match the provisioned worker identity.
- The issued certificate must be an end-entity TLS client certificate, have the client-authentication EKU, be currently valid, chain to the configured worker CA, and have a lifetime no longer than 90 days.
- Use a distinct private key per worker. Generate it on the worker host or a protected key service. Never send the private key or PKCS#12 bundle to the API.
- Store the worker PFX and its password in the worker's external secret provider. Keep the trusted root CA certificate in the API's external secret provider.
- Do not commit keys, certificates, PFX files, passwords, enrollment payloads or production secret values to Git.

## Initial enrollment

Run these commands on the worker host or a trusted provisioning workstation that will securely transfer the private files to the worker. Keep the output directory private.

```bash
mkdir -p ./worker-private
chmod 700 ./worker-private

bash deploy/certificates/create-worker-csr.sh worker-east-01 ./worker-private
```

The command creates:

- `worker-east-01.key`: a 3072-bit RSA private key with mode 0600. It stays on the worker/protected host.
- `worker-east-01.csr`: a public certificate signing request. This is the only artifact sent to the CA.

Have the CA issue a certificate for that CSR with the required client-authentication EKU and a validity period of 90 days or less. Export the issued leaf certificate and any intermediate certificates as PEM. Keep the CA root certificate separately.

Package the worker's private key and CA-signed leaf certificate into PKCS#12 on the worker host:

```bash
bash deploy/certificates/package-worker-certificate.sh \
  worker-east-01 \
  ./worker-private/worker-east-01.key \
  ./worker-private/worker-east-01.crt \
  ./worker-private/worker-root-ca.crt \
  ./worker-private/worker-east-01.pfx \
  ./worker-private/intermediate-chain.pem
```

Omit the final intermediate-chain argument when the CA signs the leaf directly. The script validates the subject identity, client-authentication purpose, CA chain and key/certificate match. It prompts for a PFX password without placing the password in command arguments and refuses to overwrite an existing bundle. The API independently validates the public certificate, including its chain, EKU, validity and maximum lifetime.

Provision the worker's PFX and password in the secret manager under the keys referenced by the chosen deployment profile. Mount the PFX read-only and configure `Worker:ClientCertificatePath` and `Worker:ClientCertificatePassword`. Do not put the PFX password in a ConfigMap, command line, image or repository.

Enroll only the public leaf/intermediate certificate with an authenticated Admin identity:

```bash
certificate_pem="$(cat ./worker-private/worker-east-01.crt)"
jq -n --arg certificatePem "$certificate_pem" \
  --argjson intermediateCertificatesPem '[]' \
  '{certificatePem: $certificatePem, intermediateCertificatesPem: $intermediateCertificatesPem}' \
  > ./worker-private/enrollment.json

curl --fail --silent --show-error \
  --request POST \
  --header "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data-binary @./worker-private/enrollment.json \
  "$SENTINELAI_API_BASE_URL/api/v1/workers/worker-east-01/certificates"
```

When an intermediate certificate is required, pass its PEM string in the `intermediateCertificatesPem` array. The endpoint is Admin-only and binds the certificate thumbprint to the already provisioned worker and tenant. The enrollment request must contain public certificates only.

Start the worker and verify that it registers and sends heartbeats. Check the Admin worker/certificate view to confirm the new certificate is enrolled and active. Do not delete the previous credentials until the replacement worker has reconnected successfully.

## Overlapping certificate rotation

1. Generate a new private key and CSR on the worker host; do not reuse the old private key.
2. Have the CA issue a new client certificate for the same provisioned worker identity. Enroll the new public certificate through the Admin endpoint.
3. During the overlap window, mount both the new PFX and old PFX read-only. Configure both certificate paths in `Worker:ClientCertificatePaths`. The worker HTTP client presents an enrolled certificate; the API checks the thumbprint binding and revocation state on authentication.
4. Restart or reconnect the worker using the new certificate. Verify successful registration and fresh heartbeats before revoking the old certificate.
5. Revoke the old certificate using the Admin certificate action or `POST /api/v1/workers/{identity}/certificates/{thumbprint}/revoke` with a reason. Confirm it no longer authenticates.
6. Remove the old PFX and password material from the worker secret provider after the overlap is complete. Keep the new active certificate as the sole configured path.

The Kubernetes ExternalSecret templates currently expose `current.pfx` and `previous.pfx` to support the overlap window. For first provisioning, populate both secret keys with the same initial PFX or tailor the ExternalSecret/worker path configuration so only the current credential is mounted. Never store an empty or placeholder PFX as a rotation credential.

## Lost or compromised worker

1. Disable the provisioned worker through the Admin workflow immediately.
2. Revoke every certificate bound to that worker and investigate the corresponding audit events.
3. Treat the private key as compromised; do not copy or recover it to a replacement host.
4. Provision a replacement worker identity (or explicitly re-enable the existing identity after review), generate a new private key/CSR and enroll a new certificate.
5. Assign capabilities and private network ranges through the Admin workflow only. Reconnect and verify the replacement worker before restoring authorized jobs.

## Validation and limitations

CI exercises the CSR and PFX scripts with a temporary test CA, verifies file permissions, checks identity mismatch rejection, and confirms the resulting PKCS#12 bundle contains a private key. API enrollment validator tests cover trusted/untrusted CA, private-key rejection, worker subject match, validity, maximum lifetime and client-auth EKU. Authenticator tests cover unknown, revoked, expired and disabled-worker certificates.

This is a manual CA and secret-manager lifecycle. Automatic renewal, a managed CA provider, live Kubernetes secret rotation, mTLS reconnect/rotation chaos tests and lost-device incident exercises remain environment-level acceptance work.
