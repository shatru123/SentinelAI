# Phase 5.0 — Architecture, data classification and threat model

**Status:** baseline recorded; cloud provider/region and service objectives remain decision gates, not silently assumed.

## Architecture decision record

### Deployment portability
- Provider-neutral app and deployment contracts are retained.
- PostgreSQL is the system of record; RabbitMQ is the durable transport; the transactional outbox remains the recovery source for committed-but-undispatched work.
- API, Web UI and Worker are independently buildable .NET 10 applications.
- Reports and evidence use a tenant/assessment-prefixed object-store contract. Production requires S3-compatible object storage with server-side encryption. The local filesystem adapter is for Development and isolated tests.
- Kubernetes packaging uses Kustomize-compatible manifests. External secret injection is an environment integration point; no cloud identity or secret material is checked into Git.
- OpenTelemetry is the telemetry contract. The OTLP endpoint and backend are environment-configured.
- A customer-network worker initiates outbound connections. No inbound route from the cloud control plane into customer networks is required.

### Provider and region
No cloud provider, account, or target region is selected by this repository change. This is intentional: deployment configuration must remain portable. Production deployment approval must record:
- provider and account/subscription/project;
- primary and recovery region;
- identity provider and OIDC issuer/audience;
- managed PostgreSQL and RabbitMQ/provider topology;
- S3-compatible object storage, KMS key ownership and region;
- external secret manager and workload identity;
- container registry, signing identity and retention;
- network/ingress owner, DNS zone and certificate authority.

The S3 adapter is one storage implementation, not a commitment to a cloud provider. Service URL/path-style options support compatible object stores.

## Service topology and trust zones

| Zone | Components | Inbound policy | Outbound policy |
|---|---|---|---|
| Public ingress | HTTPS ingress / WAF | HTTPS only to Web and end-user API routes | Web/API only |
| Control plane | API replicas, Web replicas | From ingress and private worker mTLS endpoint | PostgreSQL, RabbitMQ, object storage, OIDC, secret manager, OTLP |
| Data plane | PostgreSQL, RabbitMQ, object storage | Control-plane and worker identities only | Backups/replication and managed service endpoints |
| Worker pool | Customer-local or cloud Worker | No public inbound listener | Outbound TLS/mTLS to control plane; broker/data endpoints only where the approved deployment topology requires them |
| Operations | migration Job, telemetry, registry, backup/restore | Privileged operator / workload identity only | Registry, secret manager, telemetry, backup targets |

Do not expose PostgreSQL, RabbitMQ management, Prometheus, Tempo, Grafana, migration Jobs or worker administration to the public Internet. The worker certificate endpoint is separate from the normal user API ingress and requires TLS client certificates end-to-end; TLS termination at a proxy must preserve cryptographically verified client identity and must not rely on caller-controlled headers.

## Identity boundaries
- Operators: OIDC authorization-code flow with PKCE for Web; API validates signed JWT issuer, audience, lifetime and signing key.
- Workers: externally issued client certificate mapped by certificate thumbprint to exactly one provisioned worker and tenant. Registration payload identity/capabilities are assertions to validate, never authority.
- Workloads: service accounts/workload identity for DB, broker, object storage, secret manager and telemetry where supported.
- Humans: separate operator and approver identities; no Production passwordless identities or Admin self-approval.
- Migration: a single one-shot release Job owns schema changes. API replicas do not run migrations during startup.

## Data classification and handling

| Data | Classification | Required controls |
|---|---|---|
| Private keys, OIDC secrets, DB/broker credentials, KMS credentials | Restricted secret | External secret manager; least privilege; rotation; never in source, ConfigMaps, image layers, logs or test artifacts |
| Worker certificates, thumbprints, tenant/worker bindings | Confidential security metadata | Public certificate may be stored; private key remains on worker/key service; DB access audited; revocation checked per connection |
| Target scopes, authorization evidence, private CIDRs, assessment jobs | Confidential operational data | Tenant filtering, least privilege, expiry, immutable audit, no cross-tenant queries |
| Finding records, request metadata, redacted evidence and screenshots | Confidential security data | Tenant/assessment ownership, encryption, retention, redaction, access audit, no public object ACL |
| Reports and object-store keys | Confidential derived data | Tenant prefix, server-side encryption, private bucket, signed/authorized read path, lifecycle and reconciliation |
| Logs, traces, metrics | Internal; may contain confidential correlation data | Structured redaction, no secrets/raw evidence/auth headers, bounded attributes, retention and access control |
| SBOM, image digest, build provenance, deployment manifests | Internal supply-chain evidence | Immutable artifact storage, signed provenance, digest promotion, no secret interpolation |

## Threat model

### Assets
Operator sessions, JWTs, worker private keys and certificates, worker identity/capabilities, tenant boundaries, scope authorizations, DB rows, broker queues, outbox, object storage, audit records, build artifacts and deployment secrets.

### Trust boundaries and principal threats

| Boundary | Threat | Required mitigation / validation |
|---|---|---|
| Internet → ingress | TLS downgrade, spoofed forwarded headers, host-header abuse, request exhaustion | HTTPS/HSTS, explicit trusted proxy IPs, host allowlist, size/time/rate limits, security headers, ingress tests |
| Operator → API | Forged JWT, wrong issuer/audience, stale role, tenant claim manipulation | OIDC/JWT validation, DB role synchronization, role/tenant authorization tests |
| Worker → API | Certificate theft, impersonation, wrong-tenant cert, expired/revoked cert, replay, claimed capability escalation | CA chain + EKU + time validation, thumbprint/tenant/identity binding, revocation on each authentication, admin-only capability assignment, audit |
| API → DB | Tenant query omission, credential theft, migration race | DB least privilege, tenant-scoped queries, RLS/constraints where feasible, separate migration identity, tests |
| API/Worker → RabbitMQ | Cross-tenant queue binding, over-privileged broker user, lost/duplicated messages | Vhost/user/queue permissions, durable queues, outbox, publisher confirms, manual ACK, idempotency, reconnect/chaos tests |
| API → object storage | Path traversal, cross-tenant object read/write, public ACL, object substitution | Tenant/assessment key validation, private bucket, encryption, least-privilege workload IAM, retention and reconciliation tests |
| Cluster/workloads | Privilege escalation, secret leak, lateral movement, unbounded egress | Non-root, read-only FS, seccomp, drop caps, requests/limits, network policies, external secrets, image scan |
| CI/build supply chain | Dependency compromise, mutable tags, secret leak, untrusted artifacts | Locked central packages, secret/dependency/container/IaC scans, SBOM, signatures, digest-only promotion |
| Operations/recovery | Backup not restorable, data/object inconsistency, delayed outbox, clock skew | Restore drills, object reference audit, outbox recovery, NTP/clock-skew scenarios, measured RPO/RTO |

### Security invariants retained
- A cloud deployment does not broaden the target authorization or scanner behavior.
- Scope validation, public authorization, private CIDR intersection, worker admission, budgets, leases, cancellation and audit remain common for ordinary and scheduled jobs.
- AI cannot authorize, select or expand targets, execute tools, or declare a finding resolved.
- No active network discovery, destructive tests, credential attacks, autonomous remediation or target expansion is introduced by Phase 5.

## Provisional service objectives and recovery targets

These are planning baselines for capacity design and test harnesses. They are **not approved production commitments** until an owner accepts the values and the target workload/region is recorded.

| Measure | Provisional target | Measurement |
|---|---:|---|
| API availability | 99.9% monthly | Successful authenticated requests excluding approved maintenance |
| API read latency | p95 ≤ 300 ms | Dashboard/list endpoints at stated workload |
| API write latency | p95 ≤ 500 ms | Scope/job/schedule request acknowledgement, excluding assessment run |
| Queue-to-start delay | p95 ≤ 30 s | Outbox committed to worker lease/start |
| Outbox age | p95 ≤ 30 s; alert at 2 min | Oldest pending outbox message |
| Worker heartbeat | 30 s cadence; stale at 90 s | Latest persisted heartbeat |
| Report export | p95 ≤ 60 s within bounded report size | API request to published report |
| Database RPO | ≤ 15 min | Verified latest restorable recovery point |
| Platform RTO | ≤ 4 hours | Restore and reconcile to a usable tenant-safe service |
| Evidence/object RPO | ≤ 15 min | Object replication/backup point plus DB reference reconciliation |

A DR drill must report actual achieved RPO/RTO; a backup job's green status is not evidence of restorability. If the provider's capabilities or cost model cannot meet these targets, revise and approve the target before production readiness.

## Decisions still requiring an accountable owner
1. Cloud provider/account and primary/recovery region.
2. OIDC issuer, audience, client registration and group/role mapping.
3. CA owner and issuance/revocation service (including CRL/OCSP or authoritative DB lookup).
4. External secret manager and workload identity mechanism.
5. Production data retention, legal residency and evidence deletion policy.
6. Approval of provisional SLO, RPO and RTO values.
7. On-call owner, incident severity and escalation path.
8. Independent penetration-test scope and release approver.

Until these decisions are recorded and the workstream exit evidence exists, Phase 5 is not production-ready.

## Current customer-local worker connectivity boundary

The API now has a dedicated mTLS listener and the standalone Worker can authenticate to it for registration and heartbeat. However, the current Worker process also consumes RabbitMQ queues and reads/writes PostgreSQL directly using a separate least-privilege worker database principal and broker credentials. The mTLS HTTP client is not yet a job-streaming transport or a proxy for the worker's database/broker operations.

The Kubernetes `sentinelai-api-worker` Service is currently `ClusterIP`-only. It is intentionally not exposed through the public HTTP Ingress. Consequently, an external customer-network worker cannot yet connect to the deployed listener without an explicitly configured TCP/TLS-passthrough endpoint. A worker placed outside the cluster also needs a secure private path to its tenant-scoped broker and database endpoints.

**Do not expose PostgreSQL or RabbitMQ management/data ports publicly to make this work.** The selected cloud design must provide private connectivity (for example, approved private endpoints/VPN) or replace direct worker data access with a bounded control-plane/broker gateway. It must also provide a TCP endpoint that preserves the client TLS certificate end to end. The source ranges, endpoint DNS/SANs, certificate trust roots, broker vhost/queue permissions and database grants must be tested from a customer-network worker before this capability is called production-ready.

Until that design and its end-to-end tests exist, treat the in-cluster Worker StatefulSet as a controlled deployment profile, not proof that arbitrary customer-local workers can join a multi-tenant cloud control plane.
