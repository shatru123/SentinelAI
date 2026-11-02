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

## Messaging and tenant isolation

Each tenant has a separate job queue and each worker has a separate cancellation queue. RabbitMQ messages are durable and persistent, are consumed with manual acknowledgements, and are published on confirm-enabled channels. Retry publication completes before the original delivery is acknowledged; bounded failures are dead-lettered. The worker rejects a tenant mismatch or an unassigned job without acknowledging it.

The API writes `AgentJob`, audit data and `OutboxMessage` in one PostgreSQL transaction. The outbox dispatcher retries pending messages after broker or API restart and marks them dispatched only after confirmation.

## Audit and evidence

Record who requested a job, authorization scope and policy versions, approval decisions, worker identity, tool adapter/version, start/end time, cancellation, normalized results and evidence hashes. Avoid storing credentials or unnecessary personal data in logs.
