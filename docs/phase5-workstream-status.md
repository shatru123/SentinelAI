# Phase 5 delivery and acceptance matrix

**Implementation branch:** `phase5/cloud-operational-hardening`  
**Base:** merged Phase 4 main commit `29fc0cedc1852986422c296ebaba762a980cd31a`  
**PR:** not opened yet; one consolidated PR will be opened after the end-to-end gates pass.  
**Release status:** not production-ready. The GHCR target and main-only signed image-release workflow are configured but have not been dispatched. No cloud provider, account/region, external CA, secret manager, or on-call owner has been selected.

This matrix deliberately mirrors every Phase 5 requirement. An item is not marked complete merely because code has been added; its test, deployment or operational evidence must also exist.

## 5.0 Architecture and threat-model gate

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| Provider-neutral topology and service boundaries | In progress | [Architecture and threat model](phase5-architecture-and-threat-model.md); validate deployment manifests and actual selected cloud integration |
| Provider, account, region and recovery region | Decision required | Kept configurable; accountable owner must select and document |
| Identity provider and OIDC claims mapping | In progress | API/Web Production validation and OIDC configuration; issuer/audience/client registration and role mapping need staging IdP exercise |
| Trust zones and network flows | Baseline documented | Validate against provider ingress, private endpoints and actual network policies |
| Data classification and retention | Baseline documented | Approve residency, retention, deletion and audit requirements |
| Threat model (operator, worker, DB, broker, storage, ingress, CI, DR) | Baseline documented | Security review and abuse-case tests remain |
| SLO, workload profiles, RPO/RTO | Provisional values recorded | Owner approval and measurement under load/restore required |
| Environment boundaries and operator ownership | Decision required | Define local, integration, staging, production, on-call and escalation owners |

## 5.1 Cloud control-plane deployment

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| API/Web/Worker/PostgreSQL/RabbitMQ/object-store/telemetry topology | Manifests implemented | Kustomize base/overlays and service boundaries are in `deploy/kubernetes`; cloud service provisioning, provider selection and live deployment remain |
| Public ingress separated from internal traffic | Manifests implemented | HTTPS ingress is separate from the worker mTLS ClusterIP service; real ingress controller, firewall and trust-proxy exercise remain |
| HTTPS-only public exposure and private DB/broker/metrics/admin ports | In progress | HTTPS ingress and default-deny/network policies are defined; live cluster enforcement, private endpoints and proxy-spoof tests remain |
| Production fail-closed OIDC/database/broker/storage/TLS/secret config | Code and tests added | API/Web configuration validators and migration-only validation are covered by CI; staging IdP and real secret injection remain |
| Development identities, header auth and self-approval blocked in Production | Code and tests added | Production configuration rejects development headers, static worker tokens and self-approval; live identity-provider exercise remains |
| Liveness vs dependency readiness | Code and regression tests added | API/Web readiness is dependency-aware; integration tests cover unavailable DB/storage/worker and verify liveness remains healthy. Latest run on the current branch must pass |
| Dedicated one-shot migrations | Code and gated deployment script implemented | `--migrate` has a database-only startup path and CI smoke-tests it against a fresh PostgreSQL database. Staging/production deployment script waits for ExternalSecrets, runs migration to completion, then applies runtime workloads; live cluster/rollback test remains |
| Trusted forwarded headers, CORS, secure cookies, rate/time/body limits, headers | Partial; Web key-ring hardening added | API/Web configuration and middleware checks exist; Production Web now requires writable shared Data Protection storage plus PFX encryption, with old-certificate decryption overlap. Trusted proxy/ingress spoofing and live cookie continuity remain |
| Durable tenant-prefixed encrypted object storage | Adapter and mocked SDK tests implemented | S3 adapter enforces tenant/assessment paths, normalizes separators before traversal checks, uses AES256/KMS, and stages/publishes tenant-owned reports. Mocked SDK tests cover metadata, copy/delete, reads/404, pagination and reconciliation; current-head CI is pending. No live object-store integration test has run |
| Retention, staged cleanup and unreferenced-object reconciliation | Adapter and mocked SDK tests implemented | Staged cleanup pagination and published-report reconciliation are covered with mocked S3 responses; provider lifecycle policy, bucket versioning/retention and real object-store verification remain |
| Immutable API/Web/Worker images | Main-only release workflow implemented; not dispatched | CI builds/scans all three images. Manual `release-images.yml` is restricted to `main`, and publishes GHCR images with SBOM/provenance, GitHub build attestations and Cosign keyless signatures. No GHCR release has been created yet |
| SBOM, provenance, vulnerability and secret scanning | CI scans passed; signed release path implemented | CI run #833 generated CycloneDX SBOMs and Trivy SARIF for API/Web/Worker images; image and source CRITICAL/HIGH vulnerability/secret gates passed. Full deployment config report remains review-only for local-development relaxations. Manual release workflow additionally emits BuildKit SBOM/provenance and GitHub attestations; dispatch and registry verification remain |
| Promote exact image digest without rebuild | Script and CI test implemented | `promote-image-digests.sh` pins the exact API/Web/Worker SHA-256 digests in only the selected staging/production overlay and verifies rendered references; CI tests invalid-digest rejection and isolation of the other environment. The deployment script verifies main-branch GitHub OIDC signatures before cluster mutations. Promotion does not deploy; commit the promoted overlay before release |
| Deployment, config, rollback, schema compatibility, operator access | Not started | Runbooks and staging exercise required |

## 5.2 Worker trust and certificate lifecycle

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| Admin-approved immutable tenant/worker identity and capabilities | Existing foundation | Preserve existing provisioning boundary; add tests against mTLS enrollment |
| Production mTLS, Development-only bearer auth | In progress | Certificate auth scheme and separate 8443 listener, admin enrollment/revocation endpoints, local CSR/PFX tooling and manual lifecycle guide are present; real cluster mTLS handshake and external TCP/TLS-passthrough endpoint remain |
| Certificate bound to DB worker identity and tenant | Code and tests implemented | SHA-256 thumbprint binding, authenticator and DB migration are covered by unit tests for cross-tenant identity, unknown, revoked, expired and disabled-worker cases; final current-head CI result pending |
| CA-signed public certificate enrollment; private key never sent to API | Code and tests implemented | Admin-only endpoint accepts public certificate PEM only; enrollment validator rejects private-key material and validates CA chain, worker subject, expiry and client-auth EKU. CI exercises the CSR/PFX bootstrap tooling |
| CA issuance/revocation and trust material externalized | Partially implemented | Root/server certificate paths required from mounted secrets; external CA/secret-manager wiring pending |
| Worker key generated/stored on worker or protected key service | Manual bootstrap implemented | OpenSSL utility generates a 3072-bit worker key and CSR with private directory/file permissions; packaging validates CA chain, worker identity, EKU and key match before creating a password-protected PFX. Lifecycle CI exercise added; secret-manager handoff and real worker-host validation remain |
| Old/new certificate overlap | In progress | Worker accepts multiple mounted PFX certificates; end-to-end reconnect test pending |
| Expiry, revocation, emergency disable and audit | Code and regression tests implemented | Per-auth DB revocation lookup, Admin revoke/disable, audit events and disabled-worker rejection are present; CI exercises the relevant authenticator/enrollment suites |
| Certificate expiry <= 90 days and client-auth EKU | Code and tests implemented | API enrollment validator enforces a maximum 90-day lifetime and client-authentication EKU; integration tests cover expiry, EKU and CA-chain rejection. Latest certificate-lifecycle CI is still running |
| Wrong CA, unknown, wrong tenant, expired, not-yet-valid, revoked rejection | Code and tests implemented | API certificate-chain validation and DB authenticator binding reject untrusted, unknown, wrong-tenant, expired, not-yet-valid and revoked identities; a cross-tenant binding regression test and lifecycle CI step have been added |
| Worker cannot self-grant tenant/capabilities/CIDRs | Existing foundation | Retest role and worker-origin boundaries with certificate identity |
| TLS server validation, bounded reconnect/backoff, replay resistance | Partial | Default TLS validation preserved; heartbeat replay/idempotency and reconnect chaos coverage pending |
| Rotation, replacement, lost-device and recovery procedures | Manual runbook implemented | `docs/worker-certificate-lifecycle.md` documents initial enrollment, overlapping current/previous PFX rotation, revoke/disable, replacement and lost-device steps. Automated renewal, live reconnect/rotation chaos and real incident-recovery exercise remain |
| Job admission/cancellation/expiry/lease/capability checks retained | Existing foundation | Regression/dispatch integration tests required under certificate-auth |
| Safe Compose/local bearer migration | In progress | Compose worker switched explicitly to Development; compose and CI checks pending |

## 5.3 Kubernetes and external secret management

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| Kustomize base and local/staging/production overlays | Manifests implemented | All three overlays are checked into `deploy/kubernetes`; CI renders and schema-validates them. Staging/production placeholders must be replaced before use |
| API, Web, Worker, ingress, service accounts, config and telemetry | Manifests implemented | Base includes API/Web Deployments, worker StatefulSet, services, ingress, ConfigMap, service accounts and OTEL collector; live-cluster validation remains |
| Separate namespaces and least-privilege identities | Partial | Dedicated API/Web/Worker/Migrator service accounts and disabled token automount are defined; namespace/RBAC/workload-identity policy needs cluster validation |
| Non-root, read-only root FS, dropped capabilities, seccomp and limits | Manifests implemented | Workload manifests define non-root UID, read-only root filesystem, dropped capabilities, RuntimeDefault seccomp and resource limits; admission/live-pod checks remain |
| Startup/readiness/liveness probes, rollout, graceful shutdown and PDB | Partial | API/Web probes, rollout grace periods and disruption budgets are defined; stateful-worker shutdown and cluster rollout tests remain |
| Shared multi-replica Web Data Protection key ring | Code, manifests and cross-replica tests implemented; live storage gate open | Production validator requires a writable shared key-ring directory and current/previous private-key PFX files. Web persists keys with a stable application name, encrypts with the current certificate and decrypts with current/previous certificates. Kustomize adds the RWX PVC and staging/production ExternalSecret templates; CI verifies old-key decryption by a replacement replica. The release script checks the StorageClass, waits for PVC binding and restarts Web after secret sync. Operator StorageClass, storage encryption, live pod-replacement/cookie continuity and actual certificate rollover remain |
| HPA only for valid stateless metrics | Partial | API HPA uses CPU utilization; worker queue-aware scaling remains unimplemented. Web HPA was removed because Blazor Server keeps client circuits in process; persistent ingress cookie affinity is configured for the fixed Web replica pool |
| One-shot migration Job gated before API rollout | Sequenced workflow implemented | `deploy.sh` applies namespace/service accounts/ConfigMap and environment ExternalSecrets, waits for Ready, runs the Job with the exact runtime API digest, then applies runtime workloads. Live staging/rollback acceptance remains |
| Network policies and outbound-only customer worker | Static policy baseline implemented | Default-deny rules, worker outbound mTLS and Web egress through the operations gateway are defined. Database/broker rules currently target pods labelled in `sentinelai-data`; managed external DB/AMQP endpoints require explicit provider/CNI-specific CIDR or FQDN egress rules before deployment. CI checks only the rendered static contract; gateway allow-list and CNI enforcement remain cluster-owned |
| External secret-manager integration via workload identity/CSI/operator | Partial | External Secrets Operator `ExternalSecret` resources exist in staging/production overlays; ClusterSecretStore, provider IAM/workload identity and live refresh are environment-owned and unverified |
| No secrets in manifests/ConfigMaps/rendered output/CI logs | Partial | Docker context excludes local environment files, certificates and private keys; Kustomize CI rejects secret-like manifest values and Trivy source/image secret scans passed with zero findings. The ConfigMap `Secrets__Provider` finding is a selector-name false positive, not a secret value; external secret-store/cluster verification remains |
| Local worker outside cluster and firewall documentation | Partial; data-plane connectivity gate open | Standalone Worker uses mTLS for registration/heartbeat but still connects directly to PostgreSQL and RabbitMQ for job processing; the current mTLS Service is ClusterIP-only. External deployment needs a private, tenant-scoped data-plane path and a TCP/TLS-passthrough endpoint. Do not expose DB or broker publicly; external worker end-to-end profile remains unimplemented |
| Local, staging and production overlays | Manifests implemented | Local has Development-only resources; staging/production have separate secret references and digest placeholders. The release script handles migration sequencing without invalid nested Kustomize roots; cluster install/upgrade remains |
| Durable queue, storage classes, backup volumes, TLS, DNS and cert renewal | External environment gate | Deployment requires a provider-managed RWX encrypted StorageClass, private DB/broker endpoints, ingress/TLS and mTLS TCP passthrough; these are not provisioned or tested by the repository |
| Kustomize and Kubernetes schema validation | CI gate implemented | `kubectl kustomize` and strict `kubeconform` cover local/staging/production runtime overlays and separately validate the migration Job. External Secrets CRDs and live cluster validation remain |
| Disposable install/upgrade/uninstall | Not started | kind or equivalent ephemeral cluster gate required |
| Least privilege and NetworkPolicy live behavior | Manifest baseline only | Static manifests define least privilege and traffic boundaries; no disposable cluster/CNI policy test has run yet |
| Secret rotation without image rebuild | Partial; live refresh test pending | ExternalSecret templates now include Web Data Protection current/previous PFX and password; mounted secret updates require controlled Web rollout and old-key decryption verification. Staging refresh/rollout test remains |
| Rolling restarts preserve jobs/outbox/leases | Not started | Cluster disruption test required |

## 5.4 Load, chaos, security and disaster recovery

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| Tenant/API/schedule/report/worker/evidence workload profiles | Baseline documented | Final load scripts and calibrated target values pending |
| API, queue, outbox, scheduler, worker and report SLOs | Provisional only | Load instrumentation and agreed objective approval pending |
| Independent and combined load testing | Not started | k6 scenarios, result artifacts and thresholds required |
| Back-pressure, tenant fairness, bounded retry/concurrency/evidence | Existing limits + further tests pending | Add saturation, fairness and resource boundary tests |
| Replica/scheduler/DB/broker/worker/storage chaos | Not started | Guarded local Compose harness and acceptance automation required |
| Outbox, retry, dead-letter, lease, cancellation and reconciliation recovery | Existing Phase 4 foundation | Phase 5 multi-replica/chaos test evidence required |
| Clock skew, delayed scheduler and coalescing | Not started | Deterministic time/chaos tests required |
| Failed migration and interrupted rollout recovery | Not started | Upgrade/rollback exercise required |
| Alert thresholds, dashboards, on-call and escalation | Not started | Operational runbooks and dashboard changes required |
| Dependency/container/IaC/secret scanning | CI scan gates implemented; release evidence partial | CI builds all three runtime images, emits CycloneDX SBOMs and gates on fixed/unfixed CRITICAL/HIGH vulnerability and secret findings in images/source. Trivy configuration findings are uploaded report-only and need review; image signing/provenance and release attestation remain |
| Threat-model abuse cases and cross-tenant/worker impersonation/replay | In progress | Certificate, policy and storage tests pending |
| Independent penetration test before public exposure | External gate | Must be performed by independent assessor; cannot be substituted by CI |
| Critical/high findings fixed or approved exception | External gate | Signed report and exception record required |
| Audit integrity, retention, redaction and access | In progress | Enrollment/revocation audit added; policy and penetration review pending |
| Encrypted DB backup, PITR and retention | Not started | Provider-specific backup policy and restore jobs required |
| Evidence/object backup and DB/object consistency | Not started | Object replication/restore and reference reconciler tests required |
| Durable broker recovery and outbox as source of truth | Existing foundation | DR-specific recovery exercise required |
| Full recovery: DB, object store, broker, services, workers, history/reports | Not started | Timed isolated restore drill and evidence required |
| Measured RPO/RTO and documented loss boundary | Provisional only | Restore drill and owner approval required |
| Runbooks for deploy, migrate, cert, queue, tenant incident, restore, emergency stop | Not started | Complete operator handbook required |

## Merge and production gate

- All implementation work remains on one Phase 5 branch. A single consolidated review PR will be opened after current-head CI passes; no Phase 5 changes are merged to `main`.
- CI must pass on the final PR head, including Release build, all test suites, PostgreSQL/RabbitMQ, browser tests, Kubernetes rendering/schema checks, static security scans and Docker image scans.
- A green CI run does not by itself satisfy provider selection, staging install, external CA, independent penetration test, on-call ownership or full restore requirements.
- No PR is to be merged until the Phase 5 acceptance matrix is reconciled. The user owns the merge.
- Public production exposure remains blocked until every required exit criterion in `phase5-cloud-operational-hardening.md` has verified evidence or a formally approved exception.
