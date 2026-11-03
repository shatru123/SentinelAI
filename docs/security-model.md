# SentinelAI Security Model

## Trust boundaries

1. Browser to API: TLS, authenticated sessions/tokens, RBAC and tenant authorization.
2. API to queue: broker credentials, isolated network and least-privilege queue permissions.
3. Control plane to worker: credential-bound worker identity, tenant assignment, short-lived credentials or mTLS, signed jobs and replay protection.
4. Worker to target: strict scope enforcement, egress restrictions, rate limits and fixed adapters.
5. AI provider boundary: minimize submitted data, redact secrets and treat model output as untrusted.

## Authorization scope

Every scope must record tenant, authorizing principal, approved CIDRs/domains/repositories, exclusions, permitted check profiles, rate limits, expiration and evidence of authorization. Missing, expired or ambiguous authorization is a hard deny.

Public targets use a two-step workflow: an operator requests authorization, then a different authenticated administrator approves or revokes it. Approval records include evidence reference, verification method, authenticated approver, approval time and expiry. A requester's Boolean, verifier name or arbitrary string cannot authorize execution.

CIDR validation classifies the complete IPv4/IPv6 range, including IPv4-mapped IPv6, ULA, link-local, multicast, reserved and documentation ranges. DNS exclusions are evaluated against the hostname and every resolved address. Web scopes require exact hostname matching by default; subdomains require the explicit `AllowSubdomains` scope option, and redirects are revalidated with scheme, port, path and resolved-address checks.

Worker jobs are protected by database-backed leases owned by the authenticated worker identity. Lease renewal failure, ownership change, or expiry cancels execution before further persisted side effects. Startup recovery requeues expired and legacy unleased Running jobs, resets their executions, and treats optimistic concurrency conflicts as an expected race rather than a worker-startup failure. Worker heartbeats persist active count, capacity, health and last execution timestamps; capacity is telemetry while admission is enforced by each worker's local semaphore.

Validate IPv4 and IPv6, private/link-local/multicast/reserved ranges, mapped addresses, DNS rebinding, redirects and alternate address encodings. Resolve and validate destinations at execution time, not only when a scope is created. Re-check after every redirect and immediately before connecting.

## AI safety

- Model output is structured data validated against strict schemas.
- A deterministic policy engine makes the final allow/deny decision.
- AI cannot add targets, permissions, tools or execution budgets.
- Scanner output and repository content may contain prompt injection; delimit and treat it as data.
- Never send secrets or unnecessary raw evidence to a provider.
- Preserve provider/model/version, prompt-template version, evidence references and confidence with each analysis.
- Tool invocation is limited to explicit capabilities; no free-form shell or arbitrary network client.

## Worker hardening

Run workers non-root with read-only filesystems where possible, constrained egress, CPU/memory/process limits, bounded concurrency, timeouts, cancellation and an operator-controlled global stop switch. Worker credentials are mapped to worker identities by the API; `X-Worker-Id` is only accepted when it matches the authenticated credential binding. Shared worker tokens are restricted to explicit local-development compatibility.

Browser assessments execute with JavaScript disabled and strict policy proxying. WebSocket connections are terminated at both the loopback proxy boundary (rejecting HTTP Upgrade handshakes) and the browser route boundary (closing intercepted attempts with RFC 6455 policy code 1008 via tracked, observed task owners). Chromium lifecycle steps drain late-arriving resources on cancellation, preventing persistent processes or orphaned tasks.

## Messaging and tenant isolation

Each tenant has a separate job queue and each tenant/worker pair has a separate cancellation queue. RabbitMQ messages are durable and persistent, are consumed with manual acknowledgements, and are published on confirm-enabled channels. Cancellation payloads must match both the expected tenant and exact worker identity before acknowledgement. Retry publication completes before the original delivery is acknowledged; bounded failures are dead-lettered. The worker rejects a tenant mismatch or an unassigned job without acknowledging it.

The API writes `AgentJob`, audit data and `OutboxMessage` in one PostgreSQL transaction. The outbox dispatcher retries pending messages after broker or API restart and marks them dispatched only after confirmation.

## Audit and evidence

Record who requested a job, authorization scope and policy versions, approval decisions, worker identity, tool adapter/version, start/end time, cancellation, normalized results and evidence hashes. Avoid storing credentials or unnecessary personal data in logs. Operational URL logging is centralized and sanitized to origin-only format (scheme, host, effective port), strictly stripping credentials, session query parameters, fragments, and sensitive resource paths.
