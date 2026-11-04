# Phase 5 — Cloud and operational hardening

## Goal

Move SentinelAI from a development-oriented Compose deployment toward a production-capable control plane with independently deployable local workers. Preserve the existing authorization model, tenant boundaries, bounded assessment adapters, audit trail, transactional outbox and human approval requirements.

This is an execution plan, not a claim that production deployment is already complete. Each workstream has an explicit implementation and verification gate. Do not enable production traffic until the security and operational exit criteria pass.

## Decisions and constraints

- Keep the cloud provider and target region configurable until a deployment decision is recorded. Keep the application and deployment design portable; provider-specific identity, registry, managed database, secret manager and Kubernetes integrations must be isolated behind configuration and documented infrastructure modules.
- The production control plane must not use Development header authentication, passwordless local identities, Admin self-approval defaults or development-only API behavior.
- Operators authenticate with OIDC/JWT over TLS. Workers authenticate independently with tenant-bound, revocable credentials; the target design is mutual TLS with short-lived, rotatable client certificates.
- Never store private keys, production connection strings, API keys or secret values in Git. Kubernetes Secrets alone are not a substitute for an external secret manager.
- The cloud control plane must not require inbound connectivity to customer private networks. Local workers initiate outbound authenticated connections and receive only jobs admitted for their tenant, identity, capabilities and approved network ranges.
- Scheduled assessments and ordinary assessments must continue to share the same scope validator, authorization revalidation, worker admission, request budgets, lease, cancellation, audit and transactional outbox paths.
- No active network discovery, destructive testing, credential attacks, autonomous remediation, target expansion or AI-authorized execution is introduced by this phase.

## Workstream 5.1 — Cloud control-plane deployment

### Implementation scope

- Define a production deployment topology for the API, Blazor UI, PostgreSQL, RabbitMQ, report/evidence storage, observability collector and one or more worker pools.
- Separate public ingress from internal service traffic. Expose only the required HTTPS endpoints; keep database, broker, metrics and administrative ports private.
- Add explicit Production configuration validation. Startup must fail when required OIDC authority/audience, TLS/proxy settings, database, broker, storage, encryption, or secret-provider configuration is missing or unsafe.
- Ensure Development authentication, demo identities and self-approval cannot be enabled accidentally in Production.
- Provide readiness and liveness checks that distinguish process health from database, broker, object storage and worker availability. Do not report overall readiness as healthy when a required dependency is unavailable.
- Run EF Core migrations as a controlled deployment step/job with a single migration owner. Avoid having every API replica race to apply schema changes.
- Establish TLS termination, trusted forwarded-header handling, CORS allow-lists, secure cookies, request-size/time limits, rate limits for authentication and API entry points, and hardened security headers.
- Configure durable report/evidence storage with tenant-prefixed keys, encryption at rest, retention policy, access checks and cleanup/reconciliation. Keep temporary export artifacts private and ephemeral.
- Publish immutable API/UI/worker container images with SBOMs, image provenance and vulnerability scanning; promote the same image digest between environments.
- Document environment promotion, configuration, rollback, schema compatibility and operator access.

### Acceptance tests

- A Production startup test rejects missing or insecure authentication, broker, database and storage configuration.
- Production rejects development-header authentication, passwordless identities and Admin self-approval.
- HTTP is redirected or rejected at ingress; trusted proxy headers cannot be spoofed by untrusted clients.
- Tenant-scoped report/evidence storage cannot be read or overwritten across tenants.
- API readiness reflects required dependency state; liveness remains useful during dependency outages.
- A staged deployment applies migrations exactly once and can roll forward without losing queued/outbox work.
- An image digest can be promoted between test and production without rebuilding.

## Workstream 5.2 — Local worker connectivity and certificate rotation

### Implementation scope

- Introduce a worker enrollment lifecycle with an administrator-approved tenant, immutable worker identity, bounded capabilities and optional approved private network ranges.
- Replace long-lived static bearer-token-only production authentication with mTLS client-certificate authentication. Keep the existing local development workflow isolated to Development.
- Bind certificate identity to the provisioned worker identity and tenant; never trust tenant, identity or capabilities claimed only in a worker registration payload.
- Store CA material and certificate issuance/revocation state in an external secret manager or certificate authority. Private keys must be generated/stored on the worker or a protected key service and must not be returned to the control plane.
- Support overlapping old/new certificates during rotation, explicit expiry, revocation, emergency disable and audit. A revoked or expired certificate must fail authentication immediately after the documented revocation propagation bound.
- Define certificate issuance, renewal, rotation, recovery, worker replacement and lost-device procedures.
- Protect outbound worker connections with TLS validation, bounded reconnect/backoff, replay-resistant enrollment and heartbeat operations, and credential redaction in logs.
- Preserve job admission checks for tenant, exact worker identity, current capabilities, worker health, private CIDR authorization, job expiry and cancellation.
- Keep a safe migration period for current Compose/local bearer credentials; do not silently treat a legacy token as an mTLS identity in Production.

### Acceptance tests

- A worker certificate maps to exactly one provisioned worker and tenant.
- Wrong-tenant, unknown, expired, revoked, not-yet-valid and wrong-CA certificates are rejected.
- Rotation overlap allows the expected old/new transition; after revocation cutoff, the old certificate cannot reconnect or renew.
- A worker cannot self-grant capabilities or private network ranges.
- Worker disconnect/reconnect does not duplicate jobs or lose cancellation state.
- Certificate renewals, revocations, identity changes and failed authentication are audited without logging secrets or private key material.
- End-to-end tests verify the control plane can dispatch only to a currently authorized worker.

## Workstream 5.3 — Kubernetes and external secret management

### Implementation scope

- Add reproducible Kubernetes packaging (Helm chart or Kustomize base/overlays) for the API, Web UI, worker, ingress, service accounts, config, network policies, storage and telemetry.
- Define separate namespaces and service accounts with least privilege. Use non-root containers, read-only root filesystems where compatible, dropped Linux capabilities, seccomp defaults, resource requests/limits and pod security admission.
- Configure liveness, readiness and startup probes; controlled rolling updates; graceful shutdown; topology spread/anti-affinity where required; PodDisruptionBudgets; and Horizontal Pod Autoscalers only for stateless components with valid metrics.
- Deploy migrations as a one-shot Job gated before API rollout. Do not allow uncontrolled migration execution in every replica.
- Restrict egress to required database, broker, OIDC, secret manager, telemetry and explicitly approved worker endpoints. Network policy must not become a way to widen scan authorization.
- Integrate an external secret manager using workload identity and a supported CSI/provider integration. Secrets must not appear in Helm values, ConfigMaps, rendered manifests, CI logs, or checked-in environment files.
- Keep local workers deployable outside the cloud cluster. Provide a separate worker deployment profile for a customer network and document outbound-only firewall requirements.
- Supply environment overlays for local, integration/staging and production without copying secrets between environments.
- Document backup volumes, persistent queue storage, storage classes, ingress TLS, DNS and certificate renewal.

### Acceptance tests

- Helm/Kustomize rendering and Kubernetes schema validation pass in CI.
- A disposable cluster install, upgrade and uninstall exercise succeeds.
- Pods run with least privilege and configured resource limits; no secret values appear in rendered manifests or logs.
- Network policies deny unneeded ingress/egress while preserving control-plane, broker, telemetry and authorized worker paths.
- Rolling API and worker restarts do not lose queued/outbox jobs or bypass leases.
- Secret rotation updates the running workload without image rebuild or repository change.
- A local worker can connect outbound to the deployed control plane and remains tenant/identity/capability bound.

## Workstream 5.4 — Load, chaos, security and disaster recovery

### Performance and capacity

- Define workload profiles for concurrent tenants, API request rates, scheduled assessments, report exports, worker concurrency, queue depth, evidence volume and database growth.
- Establish measurable service objectives for API availability/latency, queue-to-start delay, assessment dispatch delay, worker heartbeat age, outbox age, error rate and report generation.
- Load-test API, PostgreSQL, RabbitMQ, outbox dispatcher, scheduler and workers independently and together.
- Validate back-pressure and fair tenant scheduling; bound due batches, retries, concurrency, response bytes, evidence size and report generation.
- Verify autoscaling does not multiply scheduled dispatches or duplicate job processing.

### Chaos and resilience

- Exercise API replica termination during dispatch, scheduler process termination, database failover, broker outage, worker loss, expired leases, network partitions and object-storage errors.
- Prove transactional outbox recovery, idempotent broker delivery, retry/dead-letter visibility, cancellation and reconciliation after restart.
- Test clock skew and delayed scheduler cycles; ensure missed intervals are coalesced and do not trigger catch-up bursts.
- Exercise failed migrations, interrupted deployments and rollback/roll-forward procedures against a production-like copy.
- Define alert thresholds, on-call runbooks, operational ownership and escalation paths.

### Security validation

- Run dependency/container/IaC scanning and secret scanning in CI.
- Perform threat modelling for operator identity, worker enrollment, certificate lifecycle, tenant isolation, broker authorization, storage access, ingress, SSRF/egress and upgrade paths.
- Run automated authorization tests for cross-tenant API access, worker impersonation, replay, revoked credentials, role changes, target authorization expiry/revocation and scheduler races.
- Conduct an independent penetration test before public production exposure. Remediate critical/high findings or formally document and approve a bounded exception before release.
- Verify audit log integrity, retention, redaction and access control.

### Backup and disaster recovery

- Set explicit RPO/RTO targets before production readiness is assessed; measure them rather than relying on backup-job success.
- Configure encrypted automated database backups, point-in-time recovery and retention. Test restoration into an isolated environment on a recurring schedule.
- Back up or replicate report/evidence objects and record consistency between database references and stored objects.
- Document broker recovery and durable queue restoration; make database outbox the recovery source for undispatched work.
- Run a full recovery exercise: restore database, storage and broker dependencies, redeploy services, reconnect workers, reconcile outbox/leases and verify tenant-scoped assessment history and reports.
- Produce evidence of recovery time, data loss boundary, reconciliation results and remaining limitations.

### Acceptance tests

- Agreed load profile meets documented latency, throughput, queue-age and resource objectives.
- No duplicate scheduled occurrence or scan job is created under replica races, retries or failover.
- Broker/database/storage interruptions recover without silently losing committed work.
- Critical/high security findings are resolved or formally dispositioned before release.
- Backup restoration and full disaster-recovery exercise meet the approved RPO/RTO.
- Runbooks cover deployment, migration, certificate rotation/revocation, queue recovery, tenant incident response, backup restore and emergency stop.

## Cross-workstream delivery sequence

1. **5.0 Architecture and threat-model gate:** record provider/region decision, topology, data classification, threat model, RPO/RTO, service objectives and environment boundaries.
2. **5.1 Cloud control plane:** production authentication/configuration, data/storage, ingress, observability, image supply chain and controlled migration path.
3. **5.2 Worker trust:** enrollment, mTLS, certificate lifecycle, revocation and worker reconnect/dispatch tests.
4. **5.3 Kubernetes:** chart/manifests, policies, secret-manager integration, migration job and staging deployment.
5. **5.4 Operational readiness:** load, chaos, security review, restore exercise, runbooks and release approval.

The sequence may overlap where safe, but no later workstream waives an earlier security or compatibility gate.

## Phase 5 exit criteria

- Production deployment is reproducible from version-controlled, secret-free infrastructure definitions.
- Production authentication is OIDC/JWT for operators and tenant-bound mTLS for workers; development authentication is impossible in Production.
- Worker certificate issuance, overlap rotation, expiry, revocation and recovery are tested end to end.
- Kubernetes deployment passes schema validation and staging install/upgrade; least privilege, network policy and external secret integration are verified.
- Load and chaos testing meets documented service objectives and demonstrates duplicate-safe dispatch/recovery.
- Security validation and independent penetration testing have no unresolved critical/high issue without an approved exception.
- Backup restore and full disaster-recovery exercise demonstrate the agreed RPO/RTO.
- Documentation, runbooks, dashboards, alerts, SBOM and release evidence are published.

## Explicit non-goals

This phase does not authorize broader target discovery, increase assessment aggressiveness, introduce autonomous remediation, or let AI choose targets or execute tools. Cloud deployment changes where the existing authorization-controlled system runs; it does not relax what the system is allowed to do.
