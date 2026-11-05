# Phase 5 delivery and acceptance matrix

**Implementation branch:** `phase5/cloud-operational-hardening`  
**Base:** merged Phase 4 main commit `29fc0cedc1852986422c296ebaba762a980cd31a`  
**PR:** not opened yet; one consolidated PR will be opened after the end-to-end gates pass.  
**Release status:** not production-ready. No provider, region, external CA, secret manager, registry or on-call owner has been selected.

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
| Liveness vs dependency readiness | Implemented in code; tests pending | API probes DB, RabbitMQ, object store, worker; Web readiness delegates to API |
| Dedicated one-shot migrations | Code and Job implemented | `--migrate` now uses a database-only startup path without loading API listener certificates; migration upgrade/rollback and cluster rollout tests remain |
| Trusted forwarded headers, CORS, secure cookies, rate/time/body limits, headers | In progress | Middleware/config added; proxy spoofing and ingress integration tests pending |
| Durable tenant-prefixed encrypted object storage | In progress | S3-compatible adapter, KMS/AES256 and tenant-key validation; fake/MinIO integration tests pending |
| Retention, staged cleanup and unreferenced-object reconciliation | In progress | S3 adapter cleanup/reconcile methods; lifecycle policy and test proof pending |
| Immutable API/Web/Worker images | Not started | CI release build and digest-only promotion still required |
| SBOM, provenance, vulnerability and secret scanning | Not started | Supply-chain workflow still required |
| Promote exact image digest without rebuild | Not started | Release pipeline and environment overlay promotion tests required |
| Deployment, config, rollback, schema compatibility, operator access | Not started | Runbooks and staging exercise required |

## 5.2 Worker trust and certificate lifecycle

| Requirement | Status | Evidence / remaining acceptance |
|---|---|---|
| Admin-approved immutable tenant/worker identity and capabilities | Existing foundation | Preserve existing provisioning boundary; add tests against mTLS enrollment |
| Production mTLS, Development-only bearer auth | In progress | Certificate auth scheme and separate 8443 mTLS listener added; CI and handshake tests pending |
| Certificate bound to DB worker identity and tenant | In progress | SHA-256 thumbprint binding model, authenticator and DB migration added; integration tests pending |
| CA-signed public certificate enrollment; private key never sent to API | In progress | Admin-only endpoint and validation added; CA-chain tests pending |
| CA issuance/revocation and trust material externalized | Partially implemented | Root/server certificate paths required from mounted secrets; external CA/secret-manager wiring pending |
| Worker key generated/stored on worker or protected key service | In progress | Worker loads PFX from mounted path; key generation/CSR/enrollment workflow and filesystem permission proof pending |
| Old/new certificate overlap | In progress | Worker accepts multiple mounted PFX certificates; end-to-end reconnect test pending |
| Expiry, revocation, emergency disable and audit | In progress | Per-auth DB revocation lookup, admin revoke/disable, audit events added; auth/DB tests pending |
| Certificate expiry <= 90 days and client-auth EKU | In progress | Enrollment validator added; tests added but not yet green |
| Wrong CA, unknown, wrong tenant, expired, not-yet-valid, revoked rejection | In progress | Test cases added; CI pending |
| Worker cannot self-grant tenant/capabilities/CIDRs | Existing foundation | Retest role and worker-origin boundaries with certificate identity |
| TLS server validation, bounded reconnect/backoff, replay resistance | Partial | Default TLS validation preserved; heartbeat replay/idempotency and reconnect chaos coverage pending |
| Rotation, replacement, lost-device and recovery procedures | Not started | Runbooks required |
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
| HPA only for valid stateless metrics | Not started | API/Web HPA plus worker queue-aware scale policy and duplicate-safety test required |
| One-shot migration Job gated before API rollout | Job and code implemented | Dedicated Job runs `--migrate`; it now avoids HTTP/mTLS configuration. Release orchestration dependency gate and rollback exercise remain |
| Network policies and outbound-only customer worker | Policy manifests implemented | Default-deny plus explicit ingress/egress policies and a worker outbound path are defined; verify enforcement on the selected CNI/cluster |
| External secret-manager integration via workload identity/CSI/operator | Partial | External Secrets Operator `ExternalSecret` resources exist in staging/production overlays; ClusterSecretStore, provider IAM/workload identity and live refresh are environment-owned and unverified |
| No secrets in manifests/ConfigMaps/rendered output/CI logs | Not started | Automated leak checks required |
| Local worker outside cluster and firewall documentation | In progress | Existing worker separate process; mTLS endpoint and deployment profile required |
| Local, staging and production overlays | Manifests implemented | Local has Development-only resources; staging/production have separate secret references and digest placeholders. Rendering is added to CI; cluster install/upgrade remains |
| Durable queue, storage classes, backup volumes, TLS, DNS and cert renewal | Not started | Manifest and runbook acceptance required |
| Kustomize and Kubernetes schema validation | CI gate added | `kubectl kustomize` and strict `kubeconform` run for all three overlays; verify the current workflow result and validate operator CRDs on the target cluster |
| Disposable install/upgrade/uninstall | Not started | kind or equivalent ephemeral cluster gate required |
| Least privilege and NetworkPolicy live behavior | Manifest baseline only | Static manifests define least privilege and traffic boundaries; no disposable cluster/CNI policy test has run yet |
| Secret rotation without image rebuild | Not started | Staging external-secret refresh test required |
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
| Dependency/container/IaC/secret scanning | Not started | CI gates required |
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

- All implementation work remains on one Phase 5 branch and will be submitted as one consolidated PR.
- CI must pass on the final PR head, including Release build, all test suites, PostgreSQL/RabbitMQ, browser tests, Kubernetes rendering/schema checks, static security scans and Docker image scans.
- A green CI run does not by itself satisfy provider selection, staging install, external CA, independent penetration test, on-call ownership or full restore requirements.
- No PR is to be merged until the Phase 5 acceptance matrix is reconciled. The user owns the merge.
- Public production exposure remains blocked until every required exit criterion in `phase5-cloud-operational-hardening.md` has verified evidence or a formally approved exception.
