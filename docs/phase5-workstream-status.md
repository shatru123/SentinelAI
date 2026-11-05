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
| API/Web/Worker/PostgreSQL/RabbitMQ/object-store/telemetry topology | In progress | Kustomize packaging and deployment documentation still required |
| Public ingress separated from internal traffic | In progress | Dedicated worker mTLS listener added; service/ingress policies still required |
| HTTPS-only public exposure and private DB/broker/metrics/admin ports | In progress | API/Web TLS/proxy controls started; ingress/network-policy deployment tests pending |
| Production fail-closed OIDC/database/broker/storage/TLS/secret config | In progress | API/Web validators added; CI and Production TestServer validation pending |
| Development identities, header auth and self-approval blocked in Production | In progress | Production scheme no longer registers bearer worker auth; tests pending |
| Liveness vs dependency readiness | Implemented in code; tests pending | API probes DB, RabbitMQ, object store, worker; Web readiness delegates to API |
| Dedicated one-shot migrations | In progress | API supports `--migrate`; Kubernetes Job and rollback/roll-forward test pending |
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
| Kustomize base and local/staging/production overlays | Not started | Manifests and rendered output required |
| API, Web, Worker, ingress, service accounts, config and telemetry | Not started | Full workload and service resources required |
| Separate namespaces and least-privilege identities | Not started | RBAC/service accounts/pod security policies required |
| Non-root, read-only root FS, dropped capabilities, seccomp and limits | Not started | Manifest assertions and live pod checks required |
| Startup/readiness/liveness probes, rollout, graceful shutdown and PDB | In progress | App probes added; manifests and rollout tests pending |
| HPA only for valid stateless metrics | Not started | API/Web HPA plus worker queue-aware scale policy and duplicate-safety test required |
| One-shot migration Job gated before API rollout | In progress | `--migrate` path added; Job/ordering/rollback test pending |
| Network policies and outbound-only customer worker | Not started | Explicit ingress/egress policy and private endpoint documentation required |
| External secret-manager integration via workload identity/CSI/operator | Not started | Provider-neutral integration contract and provider overlay required |
| No secrets in manifests/ConfigMaps/rendered output/CI logs | Not started | Automated leak checks required |
| Local worker outside cluster and firewall documentation | In progress | Existing worker separate process; mTLS endpoint and deployment profile required |
| Local, staging and production overlays | Not started | Overlay rendering and install/upgrade evidence required |
| Durable queue, storage classes, backup volumes, TLS, DNS and cert renewal | Not started | Manifest and runbook acceptance required |
| Kustomize and Kubernetes schema validation | Not started | CI and cluster validation required |
| Disposable install/upgrade/uninstall | Not started | kind or equivalent ephemeral cluster gate required |
| Least privilege and NetworkPolicy live behavior | Not started | Cluster policy tests required |
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
