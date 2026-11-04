# Phase 4.4 — Scheduled reassessment, drift detection and alerts

## Goal

Let an authorized operator schedule bounded reassessments of an existing web assessment scope, compare completed runs deterministically, and review tenant-scoped drift alerts. Every run must use the existing authorization, scope validator, scan queue, worker routing, lease, cancellation and audit paths. Scheduling is an orchestration convenience, not a new authorization capability.

## Authorization invariants

- A schedule references one existing tenant-owned `TargetScope`. It never copies targets into a new scope, edits scope contents, extends an expiry, requests approval on the operator's behalf, or widens a private network range.
- Only an Admin or Security Analyst may create, pause, resume or disable a schedule. Readers may view schedules, run history and alerts.
- Only explicitly approved web assessment profiles may be scheduled. The initial implementation supports the existing bounded passive and safe-active web profiles; it does not add network discovery or arbitrary tools.
- Schedule creation records the scope authorization fingerprint. Before every run, the scheduler reloads the scope and checks tenant ownership, active expiry, unchanged fingerprint, approved profile, current public-target authorization, and current private-worker enrollment/capabilities/range approval.
- A missing, expired, revoked, changed or otherwise invalid authorization must fail closed. The run is recorded as skipped/blocked, the schedule is paused, and an operator must review/recreate it. The scheduler never silently renews authorization.
- The original creator must still be an active operator identity in the tenant when a scheduled run is due. A changed role or missing identity blocks the run.
- Each due occurrence has a durable idempotency key based on tenant, schedule and scheduled UTC time. Multiple API replicas or retries must not create duplicate jobs for one occurrence.
- A scheduled execution uses the ordinary `AgentJob`, `WebAssessment`, outbox and worker path. It must not bypass worker capability admission, request budgets, authorization checks, lease handling, expiry or cancellation.

## Schedule controls

- Create schedules from an existing scope and an already-approved operation profile.
- Enforce a bounded interval (minimum 24 hours; maximum 90 days) and a schedule end time no later than the scope authorization expiry.
- Support pause, resume and disable. Resume does not execute immediately; the next due time is calculated from the resume action.
- Show next run, last run, last result, blocked reason and the associated assessment/job.
- Apply bounded due-item batches, optimistic concurrency on schedule state, database uniqueness for scheduled occurrences, and retry through the persisted due pointer/outbox. No scheduler lock is held while the assessment executes. A scheduler crash must not lose a due occurrence or enqueue it repeatedly.

## Drift comparison

Compare only completed assessments for the same tenant, scope, normalized target and operation profile. Use deterministic fingerprints derived from stable finding attributes; do not use AI output as a security decision.

Initial event types:

- `NewFinding`: a finding appears in the current completed run.
- `SeverityIncreased` / `SeverityDecreased`: a matching finding changes severity.
- `CoverageRegression`: a check previously completed is now unsupported, skipped, blocked or failed.
- `NoLongerObserved`: a previously present finding is absent and the corresponding current check completed successfully.

Absence alone must never be described as resolved. If the corresponding check did not complete successfully, do not infer that a finding was fixed. Keep the event wording as “no longer observed” even when the relevant check passes; only an operator-controlled finding lifecycle transition can mark remediation resolved.

Drift events store the previous/current assessment IDs, stable finding/check identifiers, event type, severity transition and a bounded summary. Tenant isolation is enforced in both queries and database relationships.

## Alerts and privacy

- The first delivery channel is an in-app, tenant-scoped notification.
- Deduplicate notifications by drift event and schedule run.
- Alert text must not contain raw evidence, credentials, user information, full query strings, URL fragments or screenshot content. Use safe path/origin display or hashes where a target reference is needed.
- External email, Slack and webhook delivery are deferred until an explicit channel configuration, secret handling, retry policy and delivery audit are designed.
- AI may summarize a drift event later, but it cannot determine that a finding is false, resolved, authorized or safe to ignore.

## API and UI

Planned Reader endpoints:
- `GET /api/v1/assessment-schedules`
- `GET /api/v1/assessment-schedules/{id}/runs`
- `GET /api/v1/assessment-drift-events`
- `GET /api/v1/notifications`

Planned Operator endpoints:
- `POST /api/v1/assessment-schedules`
- `POST /api/v1/assessment-schedules/{id}/pause`
- `POST /api/v1/assessment-schedules/{id}/resume`
- `POST /api/v1/assessment-schedules/{id}/disable`
- `POST /api/v1/assessment-drift-events/{id}/acknowledge`

The dashboard adds a Schedules workspace, run history, drift event list and notification state. UI role checks are usability controls only; API authorization remains authoritative.

## Verification and exit criteria

- Unit tests for interval/expiry validation, pause/resume/disable transitions, stable finding fingerprints and coverage-aware “no longer observed” rules.
- Integration tests for tenant isolation, role enforcement, changed/expired/revoked scope authorization, missing/disabled private workers, schedule creator role changes and unchanged target/profile enforcement.
- Concurrency tests proving two scheduler instances cannot enqueue duplicate jobs for the same occurrence; retry tests proving lease expiry does not lose or duplicate a run.
- Drift tests for new findings, severity changes, successful check coverage, incomplete/unsupported checks and no false resolution.
- Privacy tests proving alert payloads omit URL query/fragment, raw evidence and secrets.
- End-to-end browser tests for schedule creation, pause/resume, blocked authorization, run history and alert acknowledgement.
- Complete Release build, all test suites, Playwright Chromium workflow and Docker Compose validation.

## Non-goals

No active network discovery, destructive testing, credential attacks, arbitrary AI-generated commands, automatic remediation, authorization renewal, target expansion or external alert delivery is introduced by this phase.

## Follow-on work

- Phase 4.5: optional advisory summaries in exported reports, sourced only from persisted evidence-grounded analysis and clearly separated from deterministic findings.
- Phase 5: cloud control-plane deployment, worker certificate rotation, Kubernetes/secret-manager integration and operational resilience testing.

## Phase 4.4 implementation notes

The implementation branch `phase4/4.4-scheduled-reassessment-implementation` adds the following runtime pieces:

- `AssessmentSchedule`, `AssessmentScheduleRun` and `AssessmentDriftEvent` domain entities, with a persisted UTC due time, scope authorization fingerprint, creator identity, end boundary and bounded status transitions.
- A scheduler hosted by the API process (not each worker) polls every 30 seconds by default, with a configurable batch capped at 100. It re-loads the original scope and verifies that the fingerprint is unchanged before every due occurrence.
- Every scheduled occurrence is inserted in the same database transaction as the normal `AgentJob`, `AgentExecution`, `WebAssessment` and outbox message. The dispatcher uses the existing worker routing and acknowledgement pipeline. Optimistic row-version concurrency plus unique occurrence/idempotency constraints prevent multiple API instances from queuing the same scheduled time.
- A run is blocked when its scope expires or changes, its public authorization is missing/expired/revoked, the original creator no longer exists as an Admin/Security Analyst, or the assigned private worker is no longer enabled, healthy, capable and approved for the same private CIDR ranges. No authorization is extended and no new target is introduced.
- Completed assessments are compared against the prior completed assessment for the same tenant, scope and profile. Finding fingerprints use category, method, parameter and a normalized path (not query strings or fragments). Check fingerprints support explicit coverage-regression events.
- Events and in-app notifications are tenant scoped and linked by a database foreign key. Notification text contains only a safe event type and workspace pointer; no evidence, credential, query string, fragment or screenshot payload is sent. Acknowledgement marks both the drift event and its notification as read.
- The Blazor Schedules workspace exposes create, run history, pause/resume/disable, drift review and acknowledgement. API Reader/Operator policies remain authoritative.

### Verification status

The first unit tests cover lifecycle boundaries, UTC idempotency, stable finding fingerprints, severity changes, successful-check-aware absence, and coverage regression. The full Release build, PostgreSQL migration path, mult-instance dispatch, tenant/role integration tests, Playwright UI acceptance and Docker Compose validation remain pending until the implementation branch is run through CI. The phase is not marked complete until those checks pass.

### Implementation choices and limitations

The scheduler commits a due occurrence and its outbox job atomically; it does not hold a distributed lease while a multi-minute assessment is running. Competing scheduler instances are serialized by EF row-version concurrency and database uniqueness, while the existing outbox provides durable dispatch and retry. The scheduler's own database failures are retried on the next bounded polling cycle. External email, Slack and webhook delivery are intentionally not implemented in this phase.